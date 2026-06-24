//! v2 ([`ProverService`]) prover backed by the block-range-roots accumulator.
//!
//! It serves `CardanoBlocksTransactions` (v2) transaction and block proofs. As in the rebuild path
//! the per-block-range sub-tree proofs are computed on demand; the master proof comes from the
//! single append-only accumulator. v2 additionally adds a transient *partial* trailing range when
//! the tip falls inside a not-yet-sealed range, served here through the accumulator's overlay.

use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Arc};

use mithril_common::{
    StdResult,
    crypto_helper::{MKMapProof, MKTree, MKTreeNode, MKTreeStoreInMemory, MKTreeStorer},
    entities::{
        BlockHash, BlockNumber, BlockRange, CardanoBlock, CardanoBlockTransactionMkTreeNode,
        CardanoTransaction, IntoMKTreeNode, MkSetProof, TransactionHash,
    },
    signable_builder::BlockRangeRootRetriever,
};

use crate::services::{
    BlocksTransactionsRetriever, ProverService, compute_ranges_of_block_number_to_retrieve,
};

use super::BlockRangeAccumulator;

/// A [`ProverService`] (v2) that serves proofs from the block-range-roots accumulator.
pub struct AccumulatorBlocksProverService<S: MKTreeStorer> {
    blocks_transactions_retriever: Arc<dyn BlocksTransactionsRetriever>,
    block_range_root_retriever: Arc<dyn BlockRangeRootRetriever<S>>,
    accumulator: Arc<BlockRangeAccumulator<S>>,
}

impl<S: MKTreeStorer> AccumulatorBlocksProverService<S> {
    /// Create a new v2 accumulator-backed prover.
    pub fn new(
        blocks_transactions_retriever: Arc<dyn BlocksTransactionsRetriever>,
        block_range_root_retriever: Arc<dyn BlockRangeRootRetriever<S>>,
        accumulator: Arc<BlockRangeAccumulator<S>>,
    ) -> Self {
        Self {
            blocks_transactions_retriever,
            block_range_root_retriever,
            accumulator,
        }
    }

    /// Append any newly sealed block-range-roots to the accumulator.
    ///
    /// The bound is `i64::MAX` (not `u64::MAX`): the persistence query casts it to `i64`, so
    /// `u64::MAX` would wrap to `-1` and match no rows.
    async fn synchronize(&self) -> StdResult<()> {
        let block_range_roots = self
            .block_range_root_retriever
            .retrieve_block_range_roots(BlockNumber(i64::MAX as u64))
            .await?
            .collect::<Vec<_>>();

        self.accumulator.synchronize_with(block_range_roots).await
    }

    /// Compute the partial trailing range leaf, mirroring the v2 rebuild path: present only when the
    /// tip is inside a not-yet-sealed range that holds nodes.
    async fn partial_leaf(
        &self,
        up_to: BlockNumber,
    ) -> StdResult<Option<(BlockRange, MKTreeNode)>> {
        let latest_block_range = BlockRange::from_block_number(up_to);
        if latest_block_range.is_fully_covered_at(up_to)
            || self.accumulator.last_sealed_range_contains(up_to).await
        {
            return Ok(None);
        }

        let range = latest_block_range.start..latest_block_range.end.min(up_to + 1);
        let nodes = self
            .block_range_root_retriever
            .retrieve_block_ranges_nodes(range)
            .await?;
        if nodes.is_empty() {
            return Ok(None);
        }

        let root = MKTree::<MKTreeStoreInMemory>::new_from_iter(nodes)?.compute_root()?;
        let master_leaf = MKTreeNode::from(latest_block_range.to_owned()) + root;

        Ok(Some((latest_block_range, master_leaf)))
    }

    async fn compute_proof<T>(
        &self,
        up_to: BlockNumber,
        items_to_prove: Vec<T>,
        extract_block_number: fn(&T) -> BlockNumber,
    ) -> StdResult<Option<MkSetProof<T>>>
    where
        T: Into<CardanoBlockTransactionMkTreeNode> + IntoMKTreeNode + Clone,
    {
        if items_to_prove.is_empty() {
            return Ok(None);
        }
        if self.accumulator.high_water().await.is_none_or(|hw| hw < up_to) {
            self.synchronize().await?;
        }

        // 1 - The nodes to prove, in input order, and the block ranges (clamped to up_to) holding
        //     all of their sibling nodes.
        let nodes_to_prove: Vec<CardanoBlockTransactionMkTreeNode> =
            items_to_prove.iter().cloned().map(Into::into).collect();
        let ranges_to_retrieve = compute_ranges_of_block_number_to_retrieve(
            &items_to_prove,
            extract_block_number,
            ..=up_to,
        );
        let mut nodes_by_range: BTreeMap<BlockRange, Vec<CardanoBlockTransactionMkTreeNode>> =
            BTreeMap::new();
        for node in self
            .blocks_transactions_retriever
            .get_all_mk_nodes_by_ranges_of_block_numbers(ranges_to_retrieve)
            .await?
        {
            nodes_by_range
                .entry(BlockRange::from_block_number(node.block_number()))
                .or_default()
                .push(node);
        }

        // Group the proven nodes by block range, preserving the input order within each range.
        let mut proven_nodes_by_range: BTreeMap<
            BlockRange,
            Vec<CardanoBlockTransactionMkTreeNode>,
        > = BTreeMap::new();
        for node in &nodes_to_prove {
            proven_nodes_by_range
                .entry(BlockRange::from_block_number(node.block_number()))
                .or_default()
                .push(node.to_owned());
        }

        // 2 - The transient partial trailing range (changes the master tree size even if no proven
        //     node falls in it).
        let partial = self.partial_leaf(up_to).await?;

        // 3 - Per-range sub-proofs and the corresponding master-tree leaves.
        let mut candidate_sub_proofs: BTreeMap<BlockRange, MKMapProof<BlockRange>> =
            BTreeMap::new();
        let mut candidates: Vec<(BlockRange, MKTreeNode)> = Vec::new();
        for (block_range, proven_nodes) in &proven_nodes_by_range {
            let Some(range_nodes) = nodes_by_range.get(block_range) else {
                continue;
            };
            let sub_tree =
                MKTree::<MKTreeStoreInMemory>::new_from_iter(range_nodes.iter().cloned())?;
            let proven_leaves: Vec<MKTreeNode> =
                proven_nodes.iter().map(|node| node.to_owned().into()).collect();
            let sub_proof: MKMapProof<BlockRange> = sub_tree.compute_proof(&proven_leaves)?.into();
            let master_leaf = MKTreeNode::from(block_range.to_owned()) + sub_proof.compute_root();

            candidates.push((block_range.to_owned(), master_leaf));
            candidate_sub_proofs.insert(block_range.to_owned(), sub_proof);
        }
        if candidates.is_empty() {
            return Ok(None);
        }

        // 4 - Master proof from the accumulator at the tip's historical size (+ partial leaf).
        let (master_proof, kept_ranges) = self
            .accumulator
            .prove_master_with_partial(up_to, &candidates, partial)
            .await?;
        if kept_ranges.is_empty() {
            return Ok(None);
        }

        // 5 - Assemble the proof with the sub-proofs of the kept ranges only.
        let sub_proofs: BTreeMap<BlockRange, MKMapProof<BlockRange>> = kept_ranges
            .into_iter()
            .filter_map(|range| candidate_sub_proofs.remove(&range).map(|proof| (range, proof)))
            .collect();
        let proof = MKMapProof::new(master_proof, sub_proofs);

        Ok(Some(MkSetProof::<T>::new(items_to_prove, proof)))
    }
}

#[async_trait]
impl<S: MKTreeStorer> ProverService for AccumulatorBlocksProverService<S> {
    async fn compute_blocks_proofs(
        &self,
        up_to: BlockNumber,
        block_hashes: &[BlockHash],
    ) -> StdResult<Option<MkSetProof<CardanoBlock>>> {
        let blocks = self
            .blocks_transactions_retriever
            .get_block_by_hashes(block_hashes.to_vec(), up_to)
            .await?;

        self.compute_proof(up_to, blocks, |block| block.block_number).await
    }

    async fn compute_transactions_proofs(
        &self,
        up_to: BlockNumber,
        transaction_hashes: &[TransactionHash],
    ) -> StdResult<Option<MkSetProof<CardanoTransaction>>> {
        let transactions = self
            .blocks_transactions_retriever
            .get_transactions_by_hashes(transaction_hashes.to_vec(), up_to)
            .await?;

        self.compute_proof(up_to, transactions, |transaction| transaction.block_number)
            .await
    }

    async fn compute_cache(&self, _up_to: BlockNumber) -> StdResult<()> {
        // The accumulator has no per-tip cache to warm; keep it in sync with the sealed ranges.
        self.synchronize().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        ops::Range,
    };

    use async_trait::async_trait;

    use mithril_common::{
        crypto_helper::MKTreeStoreInMemory, entities::CardanoBlockWithTransactions,
        test::builder::CardanoTransactionsBuilder,
    };

    use crate::services::MithrilProverService;
    use crate::test::TestLogger;

    use super::*;

    /// A shared in-memory source of blocks/transactions and (consistent) v2 block-range-roots,
    /// driving both the rebuild path and the accumulator path with identical data.
    struct V2Fixture {
        blocks: Vec<CardanoBlockWithTransactions>,
        sealed_block_range_roots: Vec<(BlockRange, MKTreeNode)>,
    }

    impl V2Fixture {
        /// Build the fixture, sealing only the block ranges fully covered at `sealed_up_to` (so a
        /// later range can act as the partial trailing range).
        fn new(blocks: Vec<CardanoBlockWithTransactions>, sealed_up_to: BlockNumber) -> Self {
            let mut nodes_by_range: BTreeMap<
                BlockRange,
                BTreeSet<CardanoBlockTransactionMkTreeNode>,
            > = BTreeMap::new();
            for block in &blocks {
                for node in block.to_owned().into_mk_tree_node() {
                    nodes_by_range
                        .entry(BlockRange::from_block_number(node.block_number()))
                        .or_default()
                        .insert(node);
                }
            }
            let sealed_block_range_roots = nodes_by_range
                .into_iter()
                .filter(|(block_range, _)| block_range.is_fully_covered_at(sealed_up_to))
                .map(|(block_range, nodes)| {
                    let root = MKTree::<MKTreeStoreInMemory>::new_from_iter(nodes)
                        .unwrap()
                        .compute_root()
                        .unwrap();
                    (block_range, root)
                })
                .collect();

            Self {
                blocks,
                sealed_block_range_roots,
            }
        }

        fn nodes_in_range(
            &self,
            range: &Range<BlockNumber>,
        ) -> BTreeSet<CardanoBlockTransactionMkTreeNode> {
            self.blocks
                .iter()
                .filter(|block| range.contains(&block.block_number))
                .flat_map(|block| block.to_owned().into_mk_tree_node())
                .collect()
        }
    }

    #[async_trait]
    impl BlocksTransactionsRetriever for V2Fixture {
        async fn get_block_by_hashes(
            &self,
            block_hashes: Vec<BlockHash>,
            up_to: BlockNumber,
        ) -> StdResult<Vec<CardanoBlock>> {
            Ok(self
                .blocks
                .iter()
                .filter(|b| b.block_number <= up_to && block_hashes.contains(&b.block_hash))
                .map(|b| b.to_owned().into())
                .collect())
        }

        async fn get_transactions_by_hashes(
            &self,
            transaction_hashes: Vec<TransactionHash>,
            up_to: BlockNumber,
        ) -> StdResult<Vec<CardanoTransaction>> {
            Ok(self
                .blocks
                .iter()
                .flat_map(|b| b.to_owned().into_transactions())
                .filter(|t| {
                    t.block_number <= up_to && transaction_hashes.contains(&t.transaction_hash)
                })
                .collect())
        }

        async fn get_all_mk_nodes_by_ranges_of_block_numbers(
            &self,
            ranges_of_block: Vec<Range<BlockNumber>>,
        ) -> StdResult<Vec<CardanoBlockTransactionMkTreeNode>> {
            Ok(ranges_of_block
                .iter()
                .flat_map(|range| self.nodes_in_range(range))
                .collect())
        }
    }

    #[async_trait]
    impl BlockRangeRootRetriever<MKTreeStoreInMemory> for V2Fixture {
        async fn retrieve_block_range_roots<'a>(
            &'a self,
            up_to_beacon: BlockNumber,
        ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + 'a>> {
            let roots: Vec<_> = self
                .sealed_block_range_roots
                .iter()
                .filter(|(block_range, _)| block_range.start < up_to_beacon)
                .cloned()
                .collect();

            Ok(Box::new(roots.into_iter()))
        }

        async fn retrieve_block_ranges_nodes(
            &self,
            range: Range<BlockNumber>,
        ) -> StdResult<BTreeSet<CardanoBlockTransactionMkTreeNode>> {
            Ok(self.nodes_in_range(&range))
        }
    }

    #[tokio::test]
    async fn v2_accumulator_proofs_are_byte_identical_to_the_rebuild_path() {
        // 7 ranges of blocks (3 blocks each at start, start+1, start+2); only the first 6 are
        // sealed, so range [90,105) is the partial trailing range.
        let blocks = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(2)
            .blocks_per_block_range(3)
            .build_blocks_for_block_ranges(7);
        let fixture = Arc::new(V2Fixture::new(blocks.clone(), BlockNumber(90)));

        let rebuild = MithrilProverService::<MKTreeStoreInMemory>::new(
            fixture.clone(),
            fixture.clone(),
            1,
            TestLogger::stdout(),
        );
        let accumulator = Arc::new(
            BlockRangeAccumulator::new(MKTreeStoreInMemory::build().unwrap(), TestLogger::stdout())
                .unwrap(),
        );
        let accumulated =
            AccumulatorBlocksProverService::new(fixture.clone(), fixture.clone(), accumulator);

        let transactions: Vec<_> =
            blocks.iter().flat_map(|b| b.to_owned().into_transactions()).collect();
        let tx_at = |block: u64| {
            transactions
                .iter()
                .find(|t| *t.block_number == block)
                .unwrap()
                .transaction_hash
                .clone()
        };
        let tx_cases: Vec<(u64, Vec<TransactionHash>)> = vec![
            (89, vec![tx_at(30), tx_at(76)]), // sealed ranges only, no partial
            (92, vec![tx_at(30), tx_at(91)]), // partial trailing range [90,105), tx at 91
            (92, vec![tx_at(91)]),            // only a transaction in the partial range
            (47, vec![tx_at(0), tx_at(45)]),  // tip mid a sealed range, no partial
        ];
        for (up_to, hashes) in tx_cases {
            let up_to = BlockNumber(up_to);
            rebuild.compute_cache(up_to).await.unwrap();
            let from_rebuild = rebuild.compute_transactions_proofs(up_to, &hashes).await.unwrap();
            let from_accumulator =
                accumulated.compute_transactions_proofs(up_to, &hashes).await.unwrap();

            assert_eq!(
                from_rebuild, from_accumulator,
                "transaction proof differs for up_to={up_to}, hashes={hashes:?}"
            );
            assert!(
                from_accumulator.is_some(),
                "expected a proof for up_to={up_to}"
            );
            if let Some(proof) = &from_accumulator {
                proof.verify().unwrap();
            }
        }

        let block_at = |block: u64| {
            blocks
                .iter()
                .find(|b| *b.block_number == block)
                .unwrap()
                .block_hash
                .clone()
        };
        let block_cases: Vec<(u64, Vec<BlockHash>)> = vec![
            (89, vec![block_at(30), block_at(76)]),
            (92, vec![block_at(91), block_at(30)]), // partial trailing range
        ];
        for (up_to, hashes) in block_cases {
            let up_to = BlockNumber(up_to);
            rebuild.compute_cache(up_to).await.unwrap();
            let from_rebuild = rebuild.compute_blocks_proofs(up_to, &hashes).await.unwrap();
            let from_accumulator = accumulated.compute_blocks_proofs(up_to, &hashes).await.unwrap();

            assert_eq!(
                from_rebuild, from_accumulator,
                "block proof differs for up_to={up_to}"
            );
            if let Some(proof) = &from_accumulator {
                proof.verify().unwrap();
            }
        }
    }
}
