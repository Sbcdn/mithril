//! MMR accumulator prover.
//!
//! Serves Cardano transaction Merkle inclusion proofs against historical certified tips from a
//! single append-only block-range-roots accumulator, instead of rebuilding a per-tip Merkle map.
//! Proofs and roots are byte-identical to the rebuild path; only the service layer differs.
//!
//! The accumulator runs over any [`MKTreeStorer`]; the default build uses an in-memory store. The
//! optional `prover-accumulator` feature adds a redb-backed store ([`MKTreeStoreRedb`]) for
//! off-RAM, restart-persistent proof serving.

mod blocks_prover;
mod overlay;
mod prover;
#[cfg(feature = "prover-accumulator")]
mod store;

pub use blocks_prover::AccumulatorBlocksProverService;
pub use prover::AccumulatorProverService;
#[cfg(feature = "prover-accumulator")]
pub use store::MKTreeStoreRedb;

use slog::{Logger, info};
use tokio::sync::RwLock;

use mithril_common::{
    StdResult,
    crypto_helper::{MKProof, MKTree, MKTreeNode, MKTreeStorer},
    entities::{BlockNumber, BlockRange},
    logging::LoggerExtensions,
};

use overlay::OverlayStorer;

/// Number of block-range-root leaves appended per commit while (re)building the accumulator.
/// Bounds the transient memory of the underlying Merkle Mountain Range during backfill.
const DEFAULT_APPEND_CHUNK_SIZE: usize = 4096;

/// MMR size (total node count) of a Merkle Mountain Range holding `leaf_count` leaves.
///
/// Mirrors `ckb_merkle_mountain_range::leaf_index_to_mmr_size(leaf_count - 1)`, reproduced here to
/// avoid taking a direct dependency on the ckb crate from the aggregator.
fn mmr_size(leaf_count: u64) -> u64 {
    if leaf_count == 0 {
        0
    } else {
        2 * leaf_count - leaf_count.count_ones() as u64
    }
}

/// An append-only Merkle Mountain Range over the block-range-roots of one Cardano transactions
/// protocol, able to reproduce the Merkle root and inclusion proofs of any past certified tip.
///
/// The master tree holds one leaf per block range, `block_range.into() + block_range_root`, in
/// ascending block-range order — exactly the master tree a per-tip `MKMap` would build. A proof
/// for tip `B` is generated against the tree's size when it held the `n(B)` ranges certified at
/// or below `B`, so a single tree serves every tip without rebuilding.
pub struct BlockRangeAccumulator<S: MKTreeStorer> {
    inner: RwLock<AccumulatorState<S>>,
    /// A clone of the persistent store, used to overlay the transient partial trailing range
    /// (v2) without mutating the sealed nodes.
    base_store: S,
    append_chunk_size: usize,
    logger: Logger,
}

struct AccumulatorState<S: MKTreeStorer> {
    /// The append-only master tree backed by the (persistent) storer.
    tree: MKTree<S>,
    /// Sorted block-range starts; a start's position in this vector is its master-tree leaf index.
    starts: Vec<BlockNumber>,
}

impl<S: MKTreeStorer> BlockRangeAccumulator<S> {
    /// Build an empty accumulator over `store`; call [`synchronize_with`][Self::synchronize_with]
    /// to fill it from the sealed block-range-roots.
    pub fn new(store: S, logger: Logger) -> StdResult<Self> {
        let base_store = store.clone();
        let tree = MKTree::from_storer_at_size(store, 0)?;

        Ok(Self {
            inner: RwLock::new(AccumulatorState {
                tree,
                starts: Vec::new(),
            }),
            base_store,
            append_chunk_size: DEFAULT_APPEND_CHUNK_SIZE,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    /// Append every block-range-root in `block_range_roots` that is not yet accumulated, in
    /// ascending order.
    ///
    /// `block_range_roots` must be ordered by block range. On first call this backfills the whole
    /// history; afterwards it appends only the new (sealed) ranges, since block-range-roots are
    /// immutable and only ever appended. Appends are chunked so the transient build memory stays
    /// bounded.
    pub async fn synchronize_with(
        &self,
        block_range_roots: Vec<(BlockRange, MKTreeNode)>,
    ) -> StdResult<()> {
        let mut state = self.inner.write().await;
        let high_water = state.starts.last().copied();
        let appended_before = state.starts.len();

        let mut chunk_leaves: Vec<MKTreeNode> = Vec::new();
        let mut chunk_starts: Vec<BlockNumber> = Vec::new();
        for (block_range, block_range_root) in block_range_roots {
            let start = block_range.start;
            if high_water.is_some_and(|hw| start <= hw) {
                continue;
            }
            chunk_leaves.push(MKTreeNode::from(block_range) + block_range_root);
            chunk_starts.push(start);

            if chunk_leaves.len() >= self.append_chunk_size {
                state.tree.append(&chunk_leaves)?;
                state.starts.append(&mut chunk_starts);
                chunk_leaves.clear();
            }
        }
        if !chunk_leaves.is_empty() {
            state.tree.append(&chunk_leaves)?;
            state.starts.append(&mut chunk_starts);
        }

        let appended = state.starts.len() - appended_before;
        if appended > 0 {
            info!(
                self.logger, "Accumulated block-range-roots";
                "appended" => appended, "total" => state.starts.len(),
            );
        }

        Ok(())
    }

    /// The start of the most recently accumulated block range, if any.
    pub async fn high_water(&self) -> Option<BlockNumber> {
        self.inner.read().await.starts.last().copied()
    }

    /// Whether the most recently sealed block range at or below `up_to` contains `up_to`.
    ///
    /// Mirrors `is_beacon_contained_in_last_computed_range` of the v2 rebuild path: when it is
    /// true, no partial trailing range is needed.
    pub async fn last_sealed_range_contains(&self, up_to: BlockNumber) -> bool {
        let state = self.inner.read().await;
        let sealed_count = state.starts.partition_point(|start| *start < up_to);

        sealed_count > 0 && up_to < state.starts[sealed_count - 1] + BlockRange::LENGTH
    }

    /// Generate the master-tree proof for the certified tip `up_to`.
    ///
    /// `candidates` are `(block_range, master_leaf)` pairs for the block ranges that contain a
    /// proven transaction, where `master_leaf == block_range.into() + sub_proof_root`. Only ranges
    /// certified at or below `up_to` (leaf index `< n(up_to)`) are kept; the returned ranges (in
    /// ascending order) tell the caller which sub-proofs to keep so the assembled proof matches.
    pub async fn prove_master(
        &self,
        up_to: BlockNumber,
        candidates: &[(BlockRange, MKTreeNode)],
    ) -> StdResult<(MKProof, Vec<BlockRange>)> {
        self.prove_master_with_partial(up_to, candidates, None).await
    }

    /// Like [`prove_master`][Self::prove_master], but with an optional transient *partial* trailing
    /// range (v2): when `partial` is set, the master tree is proven at size `n(up_to) + 1` with the
    /// partial leaf at index `n(up_to)`, overlaid on the sealed nodes without persisting it.
    pub async fn prove_master_with_partial(
        &self,
        up_to: BlockNumber,
        candidates: &[(BlockRange, MKTreeNode)],
        partial: Option<(BlockRange, MKTreeNode)>,
    ) -> StdResult<(MKProof, Vec<BlockRange>)> {
        let state = self.inner.read().await;
        let sealed_count = state.starts.partition_point(|start| *start < up_to) as u64;
        let total_count = sealed_count + partial.is_some() as u64;

        let partial_range = partial.as_ref().map(|(block_range, _)| block_range.to_owned());
        let mut kept: Vec<(u64, BlockRange, MKTreeNode)> = candidates
            .iter()
            .filter_map(|(block_range, master_leaf)| {
                let index = if partial_range.as_ref() == Some(block_range) {
                    Some(sealed_count)
                } else {
                    state
                        .starts
                        .binary_search(&block_range.start)
                        .ok()
                        .map(|index| index as u64)
                        .filter(|&index| index < sealed_count)
                };
                index.map(|index| (index, block_range.to_owned(), master_leaf.to_owned()))
            })
            .collect();
        kept.sort_by_key(|(index, _, _)| *index);

        let leaves: Vec<(u64, MKTreeNode)> = kept
            .iter()
            .map(|(index, _, leaf)| (*index, leaf.to_owned()))
            .collect();

        let master_proof = match partial {
            Some((_, partial_leaf)) => {
                // Overlay the partial leaf (and the internal nodes its append creates) on top of
                // the sealed nodes, then prove against the resulting size; the base is untouched.
                let overlay = OverlayStorer::new(self.base_store.clone());
                let mut tree = MKTree::from_storer_at_size(overlay, mmr_size(sealed_count))?;
                tree.append(&[partial_leaf])?;
                tree.generate_proof_at_size(total_count, &leaves)?
            }
            None => state.tree.generate_proof_at_size(total_count, &leaves)?,
        };
        let kept_ranges = kept.into_iter().map(|(_, block_range, _)| block_range).collect();

        Ok((master_proof, kept_ranges))
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::crypto_helper::MKTreeStoreInMemory;

    use crate::test::TestLogger;

    use super::*;

    fn range(index: u64) -> BlockRange {
        BlockRange::from_block_number(BlockNumber(index * *BlockRange::LENGTH))
    }

    fn master_leaf(block_range: &BlockRange, root_seed: &str) -> MKTreeNode {
        MKTreeNode::from(block_range.to_owned()) + MKTreeNode::from(root_seed)
    }

    #[tokio::test]
    async fn prove_master_with_a_partial_leaf_matches_a_fresh_tree_holding_it() {
        // 6 sealed ranges plus a transient partial trailing range: proving against the accumulator
        // with the partial overlay must equal a freshly built 7-leaf tree's proof.
        let sealed: Vec<(BlockRange, MKTreeNode)> = (0..6)
            .map(|i| (range(i), MKTreeNode::from(format!("root-{i}"))))
            .collect();
        let partial_range = range(6);
        let partial_leaf = master_leaf(&partial_range, "partial-root");

        let accumulator =
            BlockRangeAccumulator::new(MKTreeStoreInMemory::build().unwrap(), TestLogger::stdout())
                .unwrap();
        accumulator.synchronize_with(sealed.clone()).await.unwrap();

        // Prove a sealed range (index 1) and the partial range (index 6); up_to falls inside the
        // partial range, so it is not yet sealed.
        let sealed_leaf = master_leaf(&sealed[1].0, "root-1");
        let candidates = vec![
            (sealed[1].0.clone(), sealed_leaf.clone()),
            (partial_range.clone(), partial_leaf.clone()),
        ];
        let up_to = BlockNumber(*partial_range.start + 5);
        let (master_proof, kept) = accumulator
            .prove_master_with_partial(
                up_to,
                &candidates,
                Some((partial_range.clone(), partial_leaf.clone())),
            )
            .await
            .unwrap();

        // Reference: a fresh tree of the 6 sealed leaves followed by the partial leaf.
        let all_leaves: Vec<MKTreeNode> = sealed
            .iter()
            .map(|(block_range, root)| MKTreeNode::from(block_range.to_owned()) + root.to_owned())
            .chain(std::iter::once(partial_leaf.clone()))
            .collect();
        let reference = MKTree::<MKTreeStoreInMemory>::new(&all_leaves).unwrap();
        let reference_proof = reference.compute_proof(&[sealed_leaf, partial_leaf]).unwrap();

        assert_eq!(vec![sealed[1].0.clone(), partial_range], kept);
        assert_eq!(
            reference_proof.to_bytes().unwrap(),
            master_proof.to_bytes().unwrap()
        );
        master_proof.verify().unwrap();
    }
}
