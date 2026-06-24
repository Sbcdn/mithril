//! v1 ([`LegacyProverService`]) prover backed by the block-range-roots accumulator.
//!
//! It assembles exactly the same `MKMapProof` as the rebuild path: per-block-range sub-tree
//! proofs are computed on demand (identical code), and the master proof is produced from the
//! single append-only accumulator at the tip's historical size instead of a freshly built map.

use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Arc};

use mithril_common::{
    StdResult,
    crypto_helper::{MKMapProof, MKTree, MKTreeNode, MKTreeStoreInMemory, MKTreeStorer},
    entities::{BlockNumber, BlockRange, CardanoTransactionsSetProof, TransactionHash},
    signable_builder::LegacyBlockRangeRootRetriever,
};

use crate::services::{LegacyProverService, TransactionsRetriever};

use super::BlockRangeAccumulator;

/// A [`LegacyProverService`] that serves transaction proofs from the block-range-roots accumulator.
pub struct AccumulatorProverService<S: MKTreeStorer> {
    transaction_retriever: Arc<dyn TransactionsRetriever>,
    block_range_root_retriever: Arc<dyn LegacyBlockRangeRootRetriever<S>>,
    accumulator: Arc<BlockRangeAccumulator<S>>,
}

impl<S: MKTreeStorer> AccumulatorProverService<S> {
    /// Create a new accumulator-backed prover.
    pub fn new(
        transaction_retriever: Arc<dyn TransactionsRetriever>,
        block_range_root_retriever: Arc<dyn LegacyBlockRangeRootRetriever<S>>,
        accumulator: Arc<BlockRangeAccumulator<S>>,
    ) -> Self {
        Self {
            transaction_retriever,
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
}

#[async_trait]
impl<S: MKTreeStorer> LegacyProverService for AccumulatorProverService<S> {
    async fn compute_transactions_proofs(
        &self,
        up_to: BlockNumber,
        transaction_hashes: &[TransactionHash],
    ) -> StdResult<Vec<CardanoTransactionsSetProof>> {
        // Make sure the accumulator covers the requested tip (sealed ranges are append-only).
        if self.accumulator.high_water().await.is_none_or(|hw| hw < up_to) {
            self.synchronize().await?;
        }

        // 1 - Resolve the proven transactions to their block ranges (only those at or below up_to).
        let transactions = self
            .transaction_retriever
            .get_by_hashes(transaction_hashes.to_vec(), up_to)
            .await?;
        if transactions.is_empty() {
            return Ok(vec![]);
        }
        let block_range_by_hash: BTreeMap<TransactionHash, BlockRange> = transactions
            .iter()
            .map(|t| {
                (
                    t.transaction_hash.clone(),
                    BlockRange::from_block_number(t.block_number),
                )
            })
            .collect();

        // Group the proven hashes by block range, preserving the input order within each range
        // (the rebuild path groups the input leaves the same way).
        let mut proven_hashes_by_range: BTreeMap<BlockRange, Vec<TransactionHash>> =
            BTreeMap::new();
        for hash in transaction_hashes {
            if let Some(block_range) = block_range_by_hash.get(hash) {
                proven_hashes_by_range
                    .entry(block_range.to_owned())
                    .or_default()
                    .push(hash.to_owned());
            }
        }

        // 2 - Fetch every transaction in the proven ranges to rebuild their sub-trees.
        let proven_ranges: Vec<BlockRange> = proven_hashes_by_range.keys().cloned().collect();
        let mut transactions_by_range: BTreeMap<BlockRange, Vec<_>> = BTreeMap::new();
        for transaction in self.transaction_retriever.get_by_block_ranges(proven_ranges).await? {
            transactions_by_range
                .entry(BlockRange::from_block_number(transaction.block_number))
                .or_default()
                .push(transaction);
        }

        // 3 - Build per-range sub-proofs and the corresponding master-tree leaves.
        let mut candidate_sub_proofs: BTreeMap<BlockRange, MKMapProof<BlockRange>> =
            BTreeMap::new();
        let mut candidates: Vec<(BlockRange, MKTreeNode)> = Vec::new();
        for (block_range, proven_hashes) in &proven_hashes_by_range {
            let Some(range_transactions) = transactions_by_range.get(block_range) else {
                continue;
            };
            let sub_tree = MKTree::<MKTreeStoreInMemory>::new(range_transactions)?;
            let proven_nodes: Vec<MKTreeNode> =
                proven_hashes.iter().map(|hash| hash.as_str().into()).collect();
            let sub_proof: MKMapProof<BlockRange> = sub_tree.compute_proof(&proven_nodes)?.into();
            let master_leaf = MKTreeNode::from(block_range.to_owned()) + sub_proof.compute_root();

            candidates.push((block_range.to_owned(), master_leaf));
            candidate_sub_proofs.insert(block_range.to_owned(), sub_proof);
        }
        if candidates.is_empty() {
            return Ok(vec![]);
        }

        // 4 - Generate the master proof against the accumulator at the tip's historical size,
        //     keeping only ranges certified at or below up_to.
        let (master_proof, kept_ranges) = self.accumulator.prove_master(up_to, &candidates).await?;
        if kept_ranges.is_empty() {
            return Ok(vec![]);
        }

        // 5 - Assemble the proof with the sub-proofs of the kept ranges only.
        let sub_proofs: BTreeMap<BlockRange, MKMapProof<BlockRange>> = kept_ranges
            .into_iter()
            .filter_map(|range| candidate_sub_proofs.remove(&range).map(|proof| (range, proof)))
            .collect();
        let proof = MKMapProof::new(master_proof, sub_proofs);

        // 6 - Report the transactions actually certified by the proof, in input order.
        let proof_leaves = proof.leaves();
        let certified: Vec<TransactionHash> = transaction_hashes
            .iter()
            .filter(|hash| proof_leaves.contains(&hash.as_str().into()))
            .cloned()
            .collect();

        Ok(vec![CardanoTransactionsSetProof::new(certified, proof)])
    }

    async fn compute_cache(&self, _up_to: BlockNumber) -> StdResult<()> {
        // The accumulator has no per-tip cache to warm; keep it in sync with the sealed ranges.
        self.synchronize().await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use async_trait::async_trait;

    use mithril_common::{
        crypto_helper::{MKTree, MKTreeStoreInMemory},
        entities::CardanoTransaction,
        signable_builder::LegacyBlockRangeRootRetriever,
        test::builder::CardanoTransactionsBuilder,
    };

    use crate::services::LegacyMithrilProverService;
    use crate::test::TestLogger;

    use super::*;

    /// A shared in-memory source of transactions and (consistent) block-range-roots, used to drive
    /// both the rebuild path and the accumulator path with identical data.
    struct DifferentialFixture {
        transactions: Vec<CardanoTransaction>,
        block_range_roots: Vec<(BlockRange, MKTreeNode)>,
    }

    impl DifferentialFixture {
        fn from_transactions(transactions: Vec<CardanoTransaction>) -> Self {
            let mut by_range: BTreeMap<BlockRange, Vec<CardanoTransaction>> = BTreeMap::new();
            for transaction in &transactions {
                by_range
                    .entry(BlockRange::from_block_number(transaction.block_number))
                    .or_default()
                    .push(transaction.clone());
            }
            let block_range_roots = by_range
                .into_iter()
                .map(|(block_range, range_transactions)| {
                    let root = MKTree::<MKTreeStoreInMemory>::new(&range_transactions)
                        .unwrap()
                        .compute_root()
                        .unwrap();
                    (block_range, root)
                })
                .collect();

            Self {
                transactions,
                block_range_roots,
            }
        }
    }

    #[async_trait]
    impl TransactionsRetriever for DifferentialFixture {
        async fn get_by_hashes(
            &self,
            hashes: Vec<TransactionHash>,
            up_to: BlockNumber,
        ) -> StdResult<Vec<CardanoTransaction>> {
            Ok(self
                .transactions
                .iter()
                .filter(|t| t.block_number <= up_to && hashes.contains(&t.transaction_hash))
                .cloned()
                .collect())
        }

        async fn get_by_block_ranges(
            &self,
            block_ranges: Vec<BlockRange>,
        ) -> StdResult<Vec<CardanoTransaction>> {
            Ok(self
                .transactions
                .iter()
                .filter(|t| block_ranges.contains(&BlockRange::from_block_number(t.block_number)))
                .cloned()
                .collect())
        }
    }

    #[async_trait]
    impl LegacyBlockRangeRootRetriever<MKTreeStoreInMemory> for DifferentialFixture {
        async fn retrieve_block_range_roots<'a>(
            &'a self,
            up_to_beacon: BlockNumber,
        ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + 'a>> {
            let roots: Vec<_> = self
                .block_range_roots
                .iter()
                .filter(|(block_range, _)| block_range.start < up_to_beacon)
                .cloned()
                .collect();

            Ok(Box::new(roots.into_iter()))
        }
    }

    #[tokio::test]
    async fn accumulator_v1_proofs_are_byte_identical_to_the_rebuild_path() {
        // 6 block ranges (starts 0,15,30,45,60,75), 3 blocks each, 2 transactions per block.
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(2)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(6);
        let fixture = Arc::new(DifferentialFixture::from_transactions(transactions.clone()));

        let current = LegacyMithrilProverService::new(
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
            AccumulatorProverService::new(fixture.clone(), fixture.clone(), accumulator);

        let hash = |i: usize| transactions[i].transaction_hash.clone();
        let all_hashes: Vec<TransactionHash> =
            transactions.iter().map(|t| t.transaction_hash.clone()).collect();
        let cases: Vec<(u64, Vec<TransactionHash>)> = vec![
            (90, vec![hash(0), hash(10), hash(20), hash(35)]), // transactions across 4 ranges, all tips
            (45, vec![hash(0), hash(10)]),                     // half the ranges certified
            (30, vec![hash(0)]),                               // a single range
            (90, all_hashes),                                  // every transaction
            (15, vec![hash(0)]),                               // up_to exactly on a range boundary
            (16, vec![hash(0), hash(6)]),                      // tx in the range that starts at 15
        ];

        for (up_to, mut hashes) in cases {
            let up_to = BlockNumber(up_to);
            hashes.sort();
            hashes.dedup();

            current.compute_cache(up_to).await.unwrap();
            let from_rebuild = current.compute_transactions_proofs(up_to, &hashes).await.unwrap();
            let from_accumulator =
                accumulated.compute_transactions_proofs(up_to, &hashes).await.unwrap();

            // Structural equality of the proofs implies byte-identical wire bytes, since the
            // proof's `to_bytes` (bincode) is deterministic from its structure.
            assert_eq!(
                from_rebuild, from_accumulator,
                "proofs differ for up_to={up_to}, hashes={hashes:?}"
            );
            assert!(
                !from_accumulator.is_empty(),
                "expected a proof for up_to={up_to}"
            );
            for proof in from_rebuild.iter().chain(from_accumulator.iter()) {
                proof.verify().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn certifies_only_transactions_in_ranges_sealed_at_or_below_the_tip() {
        // 2 ranges: [0,15) and [15,30). A transaction at block 15 belongs to range [15,30),
        // which is NOT sealed at up_to=15, so it must not be certified while one in range [0,15)
        // is. (The rebuild path errors here, enriching a range absent from the tip's map.)
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .build_transactions_for_block_ranges(2);
        let fixture = Arc::new(DifferentialFixture::from_transactions(transactions.clone()));
        let accumulator = Arc::new(
            BlockRangeAccumulator::new(MKTreeStoreInMemory::build().unwrap(), TestLogger::stdout())
                .unwrap(),
        );
        let prover = AccumulatorProverService::new(fixture.clone(), fixture.clone(), accumulator);

        let in_first_range = transactions.iter().find(|t| *t.block_number < 15).unwrap();
        let at_boundary = transactions.iter().find(|t| *t.block_number == 15).unwrap();

        let proofs = prover
            .compute_transactions_proofs(
                BlockNumber(15),
                &[
                    in_first_range.transaction_hash.clone(),
                    at_boundary.transaction_hash.clone(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(1, proofs.len());
        assert_eq!(
            &[in_first_range.transaction_hash.clone()],
            proofs[0].transactions_hashes()
        );
        proofs[0].verify().unwrap();
    }
}
