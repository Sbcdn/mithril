use async_trait::async_trait;
use slog::{Logger, info};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use mithril_common::{
    StdResult,
    crypto_helper::{MKTree, MKTreeStorer},
    entities::{
        BlockNumber, BlockRange, CardanoTransaction, CardanoTransactionsSetProof, TransactionHash,
    },
    logging::LoggerExtensions,
    signable_builder::LegacyBlockRangeRootRetriever,
};

use super::prover_cache::KeyedMerkleMapCache;

/// Legacy Prover service is the cryptographic engine in charge of producing cryptographic proofs for transactions
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait LegacyProverService: Sync + Send {
    /// Compute the cryptographic proofs for the given transactions
    async fn compute_transactions_proofs(
        &self,
        up_to: BlockNumber,
        transaction_hashes: &[TransactionHash],
    ) -> StdResult<Vec<CardanoTransactionsSetProof>>;

    /// Compute the cache
    async fn compute_cache(&self, up_to: BlockNumber) -> StdResult<()>;
}

/// Transactions retriever
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TransactionsRetriever: Sync + Send {
    /// Get a list of transactions by hashes using chronological order
    async fn get_by_hashes(
        &self,
        hashes: Vec<TransactionHash>,
        up_to: BlockNumber,
    ) -> StdResult<Vec<CardanoTransaction>>;

    /// Get by block ranges
    async fn get_by_block_ranges(
        &self,
        block_ranges: Vec<BlockRange>,
    ) -> StdResult<Vec<CardanoTransaction>>;
}

/// Legacy Mithril prover
pub struct LegacyMithrilProverService<S: MKTreeStorer> {
    transaction_retriever: Arc<dyn TransactionsRetriever>,
    block_range_root_retriever: Arc<dyn LegacyBlockRangeRootRetriever<S>>,
    cache: KeyedMerkleMapCache<S>,
    logger: Logger,
}

impl<S: MKTreeStorer> LegacyMithrilProverService<S> {
    /// Create a new Mithril prover.
    ///
    /// `mk_map_pool_size` is the number of identical maps kept per certified tip;
    /// `cache_max_entries` is the number of tips cached before least-recently-used
    /// eviction.
    pub fn new(
        transaction_retriever: Arc<dyn TransactionsRetriever>,
        block_range_root_retriever: Arc<dyn LegacyBlockRangeRootRetriever<S>>,
        mk_map_pool_size: usize,
        cache_max_entries: usize,
        logger: Logger,
    ) -> Self {
        Self {
            transaction_retriever,
            block_range_root_retriever,
            cache: KeyedMerkleMapCache::new(cache_max_entries, mk_map_pool_size),
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    /// Return the cached Merkle map pool for `up_to`, building it from the
    /// block-range-roots at or below `up_to` on a cache miss.
    async fn cached_pool_for(
        &self,
        up_to: BlockNumber,
    ) -> StdResult<Arc<super::prover_cache::CachedMerkleMapPool<S>>> {
        self.cache
            .get_or_try_init(up_to, || async {
                self.block_range_root_retriever
                    .compute_merkle_map_from_block_range_roots(up_to)
                    .await
            })
            .await
    }

    async fn get_block_ranges(
        &self,
        transaction_hashes: &[TransactionHash],
        up_to: BlockNumber,
    ) -> StdResult<Vec<BlockRange>> {
        let transactions = self
            .transaction_retriever
            .get_by_hashes(transaction_hashes.to_vec(), up_to)
            .await?;
        let block_ranges = transactions
            .iter()
            .map(|t| BlockRange::from_block_number(t.block_number))
            .collect::<BTreeSet<_>>();

        Ok(block_ranges.into_iter().collect::<Vec<_>>())
    }

    /// Get all the transactions of the block ranges
    async fn get_all_transactions_for_block_ranges(
        &self,
        block_ranges: &[BlockRange],
    ) -> StdResult<HashMap<BlockRange, Vec<CardanoTransaction>>> {
        let mut block_ranges_map = HashMap::new();
        let transactions = self
            .transaction_retriever
            .get_by_block_ranges(block_ranges.to_vec())
            .await?;
        for transaction in transactions {
            let block_range = BlockRange::from_block_number(transaction.block_number);
            let block_range_transactions: &mut Vec<_> =
                block_ranges_map.entry(block_range).or_insert(vec![]);
            block_range_transactions.push(transaction)
        }

        Ok(block_ranges_map)
    }
}

#[async_trait]
impl<S: MKTreeStorer> LegacyProverService for LegacyMithrilProverService<S> {
    async fn compute_transactions_proofs(
        &self,
        up_to: BlockNumber,
        transaction_hashes: &[TransactionHash],
    ) -> StdResult<Vec<CardanoTransactionsSetProof>> {
        // 1 - Compute the set of block ranges with transactions to prove
        let block_ranges_transactions = self.get_block_ranges(transaction_hashes, up_to).await?;
        let block_range_transactions = self
            .get_all_transactions_for_block_ranges(&block_ranges_transactions)
            .await?;

        // 2 - Compute block ranges sub Merkle trees
        let mk_trees: StdResult<Vec<(BlockRange, MKTree<S>)>> = block_range_transactions
            .into_iter()
            .map(|(block_range, transactions)| {
                let mk_tree = MKTree::new(&transactions)?;
                Ok((block_range, mk_tree))
            })
            .collect();
        let mk_trees = BTreeMap::from_iter(mk_trees?);

        // 3 - Acquire the cached block range roots Merkle map for this up_to
        let pool = self.cached_pool_for(up_to).await?;
        let acquire_timeout = Duration::from_millis(1000);
        let mut mk_map = pool.acquire_resource(acquire_timeout)?;

        // 4 - Enrich the Merkle map with the block ranges Merkle trees
        for (block_range, mk_tree) in mk_trees {
            mk_map.replace(block_range, mk_tree.into())?;
        }

        // 5 - Compute the proof for all transactions
        match mk_map.compute_proof(transaction_hashes) {
            Ok(mk_proof) => {
                pool.give_back_resource_pool_item(mk_map)?;
                let mk_proof_leaves = mk_proof.leaves();
                let transaction_hashes_certified: Vec<TransactionHash> = transaction_hashes
                    .iter()
                    .filter(|hash| mk_proof_leaves.contains(&hash.as_str().into()))
                    .cloned()
                    .collect();

                Ok(vec![CardanoTransactionsSetProof::new(
                    transaction_hashes_certified,
                    mk_proof,
                )])
            }
            _ => Ok(vec![]),
        }
    }

    async fn compute_cache(&self, up_to: BlockNumber) -> StdResult<()> {
        info!(
            self.logger, "Computing the Merkle map cache entry";
            "up_to_block_number" => *up_to,
        );
        self.cached_pool_for(up_to).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use mockall::mock;
    use mockall::predicate::eq;

    use mithril_common::crypto_helper::{
        MKMap, MKMapNode, MKTreeNode, MKTreeStoreInMemory, MKTreeStorer,
    };
    use mithril_common::entities::CardanoTransaction;
    use mithril_common::test::builder::CardanoTransactionsBuilder;
    use mithril_common::test::crypto_helper::MKTreeTestExtension;

    use crate::test::TestLogger;

    use super::*;

    mock! {
        pub LegacyBlockRangeRootRetrieverImpl<S: MKTreeStorer> { }

        #[async_trait]
        impl<S: MKTreeStorer> LegacyBlockRangeRootRetriever<S> for LegacyBlockRangeRootRetrieverImpl<S> {
            async fn retrieve_block_range_roots<'a>(
                &'a self,
                up_to_beacon: BlockNumber,
            ) -> StdResult<Box<dyn Iterator<Item = (BlockRange, MKTreeNode)> + 'a>>;

            async fn compute_merkle_map_from_block_range_roots(
                &self,
                up_to_beacon: BlockNumber,
            ) -> StdResult<MKMap<BlockRange, MKMapNode<BlockRange, S>, S>>;
        }
    }

    mod test_data {
        use mithril_common::crypto_helper::MKTreeStoreInMemory;

        use super::*;

        pub fn filter_transactions_for_indices(
            indices: &[usize],
            transactions: &[CardanoTransaction],
        ) -> Vec<CardanoTransaction> {
            transactions
                .iter()
                .enumerate()
                .filter(|(i, _)| indices.contains(i))
                .map(|(_, t)| t.to_owned())
                .collect()
        }

        pub fn map_to_transaction_hashes(
            transactions: &[CardanoTransaction],
        ) -> Vec<TransactionHash> {
            transactions.iter().map(|t| t.transaction_hash.clone()).collect()
        }

        pub fn transactions_group_by_block_range(
            transactions: &[CardanoTransaction],
        ) -> BTreeMap<BlockRange, Vec<CardanoTransaction>> {
            let mut block_ranges_map = BTreeMap::new();
            for transaction in transactions {
                let block_range = BlockRange::from_block_number(transaction.block_number);
                let block_range_transactions: &mut Vec<_> =
                    block_ranges_map.entry(block_range).or_insert(vec![]);
                block_range_transactions.push(transaction.to_owned())
            }

            block_ranges_map
        }

        pub fn filter_transactions_for_block_ranges(
            block_ranges: &[BlockRange],
            transactions: &[CardanoTransaction],
        ) -> Vec<CardanoTransaction> {
            transactions
                .iter()
                .filter(|t| block_ranges.contains(&BlockRange::from_block_number(t.block_number)))
                .map(|t| t.to_owned())
                .collect()
        }

        pub fn compute_mk_map_from_block_ranges_map(
            block_ranges_map: BTreeMap<BlockRange, Vec<CardanoTransaction>>,
        ) -> MKMap<BlockRange, MKMapNode<BlockRange, MKTreeStoreInMemory>, MKTreeStoreInMemory>
        {
            MKMap::new_from_iter(
                block_ranges_map.into_iter().map(|(block_range, transactions)| {
                    (
                        block_range,
                        MKMapNode::TreeNode(
                            MKTree::<MKTreeStoreInMemory>::compute_root_from_iter(&transactions)
                                .unwrap(),
                        ),
                    )
                }),
            )
            .unwrap()
        }

        pub fn compute_beacon_from_transactions(
            transactions: &[CardanoTransaction],
        ) -> BlockNumber {
            let max_transaction = transactions.iter().max_by_key(|t| t.block_number).unwrap();
            max_transaction.block_number
        }

        pub struct TestData {
            pub transaction_hashes_to_prove: Vec<TransactionHash>,
            pub block_ranges_map: BTreeMap<BlockRange, Vec<CardanoTransaction>>,
            pub block_ranges_to_prove: Vec<BlockRange>,
            pub all_transactions_in_block_ranges_to_prove: Vec<CardanoTransaction>,
            pub beacon: BlockNumber,
        }

        pub fn build_test_data(
            transactions_to_prove: &[CardanoTransaction],
            transactions: &[CardanoTransaction],
        ) -> TestData {
            let transaction_hashes_to_prove = map_to_transaction_hashes(transactions_to_prove);
            let block_ranges_map = transactions_group_by_block_range(transactions);
            let block_ranges_map_to_prove =
                transactions_group_by_block_range(transactions_to_prove);
            let block_ranges_to_prove =
                block_ranges_map_to_prove.keys().cloned().collect::<Vec<_>>();
            let all_transactions_in_block_ranges_to_prove =
                filter_transactions_for_block_ranges(&block_ranges_to_prove, transactions);
            let beacon = compute_beacon_from_transactions(transactions);

            TestData {
                transaction_hashes_to_prove,
                block_ranges_map,
                block_ranges_to_prove,
                all_transactions_in_block_ranges_to_prove,
                beacon,
            }
        }
    }

    fn build_prover<F, G, S: MKTreeStorer + 'static>(
        transaction_retriever_mock_config: F,
        block_range_root_retriever_mock_config: G,
    ) -> LegacyMithrilProverService<S>
    where
        F: FnOnce(&mut MockTransactionsRetriever),
        G: FnOnce(&mut MockLegacyBlockRangeRootRetrieverImpl<S>),
    {
        let mut transaction_retriever = MockTransactionsRetriever::new();
        transaction_retriever_mock_config(&mut transaction_retriever);
        let mut block_range_root_retriever = MockLegacyBlockRangeRootRetrieverImpl::new();
        block_range_root_retriever_mock_config(&mut block_range_root_retriever);
        let mk_map_pool_size = 1;
        let cache_max_entries = 4;

        LegacyMithrilProverService::new(
            Arc::new(transaction_retriever),
            Arc::new(block_range_root_retriever),
            mk_map_pool_size,
            cache_max_entries,
            TestLogger::stdout(),
        )
    }

    #[tokio::test]
    async fn compute_proof_for_one_set_of_three_certified_transactions() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transactions_to_prove =
            test_data::filter_transactions_for_indices(&[1, 2, 4], &transactions);
        let test_data = test_data::build_test_data(&transactions_to_prove, &transactions);
        let prover = build_prover(
            |transaction_retriever_mock| {
                let transaction_hashes_to_prove = test_data.transaction_hashes_to_prove.clone();
                let transactions_to_prove = transactions_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_hashes()
                    .with(eq(transaction_hashes_to_prove), eq(test_data.beacon))
                    .return_once(move |_, _| Ok(transactions_to_prove));

                let block_ranges_to_prove = test_data.block_ranges_to_prove.clone();
                let all_transactions_in_block_ranges_to_prove =
                    test_data.all_transactions_in_block_ranges_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_block_ranges()
                    .with(eq(block_ranges_to_prove))
                    .return_once(move |_| Ok(all_transactions_in_block_ranges_to_prove));
            },
            |block_range_root_retriever_mock| {
                let block_ranges_map = test_data.block_ranges_map.clone();
                block_range_root_retriever_mock
                    .expect_compute_merkle_map_from_block_range_roots()
                    .return_once(|_| {
                        Ok(test_data::compute_mk_map_from_block_ranges_map(
                            block_ranges_map,
                        ))
                    });
            },
        );
        prover.compute_cache(test_data.beacon).await.unwrap();

        let transactions_set_proof = prover
            .compute_transactions_proofs(test_data.beacon, &test_data.transaction_hashes_to_prove)
            .await
            .unwrap();

        assert_eq!(transactions_set_proof.len(), 1);
        assert_eq!(
            transactions_set_proof[0].transactions_hashes(),
            test_data.transaction_hashes_to_prove
        );
        transactions_set_proof[0].verify().unwrap();
    }

    #[tokio::test]
    async fn cant_compute_proof_for_not_yet_certified_transaction() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transactions_to_prove =
            test_data::filter_transactions_for_indices(&[1, 2, 4], &transactions);
        let test_data = test_data::build_test_data(&transactions_to_prove, &transactions);
        let prover = build_prover(
            |transaction_retriever_mock| {
                let transaction_hashes_to_prove = test_data.transaction_hashes_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_hashes()
                    .with(eq(transaction_hashes_to_prove), eq(test_data.beacon))
                    .return_once(move |_, _| Ok(vec![]));
                transaction_retriever_mock
                    .expect_get_by_block_ranges()
                    .with(eq(vec![]))
                    .return_once(move |_| Ok(vec![]));
            },
            |block_range_root_retriever_mock| {
                let block_ranges_map = test_data.block_ranges_map.clone();
                block_range_root_retriever_mock
                    .expect_compute_merkle_map_from_block_range_roots()
                    .return_once(|_| {
                        Ok(test_data::compute_mk_map_from_block_ranges_map(
                            block_ranges_map,
                        ))
                    });
            },
        );
        prover.compute_cache(test_data.beacon).await.unwrap();

        let transactions_set_proof = prover
            .compute_transactions_proofs(test_data.beacon, &test_data.transaction_hashes_to_prove)
            .await
            .unwrap();

        assert_eq!(transactions_set_proof.len(), 0);
    }

    #[tokio::test]
    async fn cant_compute_proof_for_unknown_transaction() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transactions_to_prove = test_data::filter_transactions_for_indices(&[], &transactions);
        let mut test_data = test_data::build_test_data(&transactions_to_prove, &transactions);
        test_data.transaction_hashes_to_prove = vec!["tx-unknown-123".to_string()];
        let prover = build_prover(
            |transaction_retriever_mock| {
                let transaction_hashes_to_prove = test_data.transaction_hashes_to_prove.clone();
                let transactions_to_prove = transactions_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_hashes()
                    .with(eq(transaction_hashes_to_prove), eq(test_data.beacon))
                    .return_once(move |_, _| Ok(transactions_to_prove));

                let block_ranges_to_prove = test_data.block_ranges_to_prove.clone();
                let all_transactions_in_block_ranges_to_prove =
                    test_data.all_transactions_in_block_ranges_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_block_ranges()
                    .with(eq(block_ranges_to_prove))
                    .return_once(move |_| Ok(all_transactions_in_block_ranges_to_prove));
            },
            |block_range_root_retriever_mock| {
                let block_ranges_map = test_data.block_ranges_map.clone();
                block_range_root_retriever_mock
                    .expect_compute_merkle_map_from_block_range_roots()
                    .return_once(|_| {
                        Ok(test_data::compute_mk_map_from_block_ranges_map(
                            block_ranges_map,
                        ))
                    });
            },
        );
        prover.compute_cache(test_data.beacon).await.unwrap();

        let transactions_set_proof = prover
            .compute_transactions_proofs(test_data.beacon, &test_data.transaction_hashes_to_prove)
            .await
            .unwrap();

        assert_eq!(transactions_set_proof.len(), 0);
    }

    #[tokio::test]
    async fn compute_proof_for_one_set_of_three_certified_transactions_and_two_unknowns() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transactions_to_prove =
            test_data::filter_transactions_for_indices(&[1, 2, 4], &transactions);
        let transaction_hashes_unknown =
            vec!["tx-unknown-123".to_string(), "tx-unknown-456".to_string()];
        let mut test_data = test_data::build_test_data(&transactions_to_prove, &transactions);
        let transaction_hashes_known = test_data.transaction_hashes_to_prove.clone();
        test_data.transaction_hashes_to_prove = [
            test_data.transaction_hashes_to_prove.clone(),
            transaction_hashes_unknown,
        ]
        .concat();
        let prover = build_prover(
            |transaction_retriever_mock| {
                let transaction_hashes_to_prove = test_data.transaction_hashes_to_prove.clone();
                let transactions_to_prove = transactions_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_hashes()
                    .with(eq(transaction_hashes_to_prove), eq(test_data.beacon))
                    .return_once(move |_, _| Ok(transactions_to_prove));

                let block_ranges_to_prove = test_data.block_ranges_to_prove.clone();
                let all_transactions_in_block_ranges_to_prove =
                    test_data.all_transactions_in_block_ranges_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_block_ranges()
                    .with(eq(block_ranges_to_prove))
                    .return_once(move |_| Ok(all_transactions_in_block_ranges_to_prove));
            },
            |block_range_root_retriever_mock| {
                let block_ranges_map = test_data.block_ranges_map.clone();
                block_range_root_retriever_mock
                    .expect_compute_merkle_map_from_block_range_roots()
                    .return_once(|_| {
                        Ok(test_data::compute_mk_map_from_block_ranges_map(
                            block_ranges_map,
                        ))
                    });
            },
        );
        prover.compute_cache(test_data.beacon).await.unwrap();

        let transactions_set_proof = prover
            .compute_transactions_proofs(test_data.beacon, &test_data.transaction_hashes_to_prove)
            .await
            .unwrap();

        assert_eq!(transactions_set_proof.len(), 1);
        assert_eq!(
            transactions_set_proof[0].transactions_hashes(),
            transaction_hashes_known
        );
        transactions_set_proof[0].verify().unwrap();
    }

    #[tokio::test]
    async fn cant_compute_proof_if_transaction_retriever_fails() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transactions_to_prove =
            test_data::filter_transactions_for_indices(&[1, 2, 4], &transactions);
        let test_data = test_data::build_test_data(&transactions_to_prove, &transactions);
        let prover = build_prover::<_, _, MKTreeStoreInMemory>(
            |transaction_retriever_mock| {
                transaction_retriever_mock
                    .expect_get_by_hashes()
                    .returning(|_, _| Err(anyhow!("Error")));
            },
            |block_range_root_retriever_mock| {
                block_range_root_retriever_mock
                    .expect_compute_merkle_map_from_block_range_roots()
                    .return_once(|_| MKMap::new(&[]));
            },
        );
        prover.compute_cache(test_data.beacon).await.unwrap();

        prover
            .compute_transactions_proofs(test_data.beacon, &test_data.transaction_hashes_to_prove)
            .await
            .expect_err("Should have failed because of transaction retriever failure");
    }

    #[tokio::test]
    async fn cant_compute_proof_if_block_range_root_retriever_fails() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transactions_to_prove =
            test_data::filter_transactions_for_indices(&[1, 2, 4], &transactions);
        let test_data = test_data::build_test_data(&transactions_to_prove, &transactions);
        let prover = build_prover::<_, _, MKTreeStoreInMemory>(
            |transaction_retriever_mock| {
                let transactions_to_prove = transactions_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_hashes()
                    .return_once(move |_, _| Ok(transactions_to_prove));

                let all_transactions_in_block_ranges_to_prove =
                    test_data.all_transactions_in_block_ranges_to_prove.clone();
                transaction_retriever_mock
                    .expect_get_by_block_ranges()
                    .return_once(move |_| Ok(all_transactions_in_block_ranges_to_prove));
            },
            |block_range_root_retriever_mock| {
                block_range_root_retriever_mock
                    .expect_compute_merkle_map_from_block_range_roots()
                    .return_once(|_| Err(anyhow!("Error")));
            },
        );

        prover
            .compute_transactions_proofs(test_data.beacon, &test_data.transaction_hashes_to_prove)
            .await
            .expect_err("Should have failed because of block range root retriever failure");
    }

    #[tokio::test]
    async fn proves_each_up_to_against_its_own_block_range_roots_map() {
        let transactions = CardanoTransactionsBuilder::new()
            .max_transactions_per_block(1)
            .blocks_per_block_range(3)
            .build_transactions_for_block_ranges(5);
        let transaction_to_prove = test_data::filter_transactions_for_indices(&[1], &transactions);
        let transaction_hashes = test_data::map_to_transaction_hashes(&transaction_to_prove);

        // The lower tip is certified over the first two block ranges only, the higher tip
        // over all of them; both cover the proven transaction's range.
        let all_block_ranges = test_data::transactions_group_by_block_range(&transactions);
        let lower_block_ranges: BTreeMap<_, _> = all_block_ranges
            .iter()
            .take(2)
            .map(|(range, txs)| (range.to_owned(), txs.to_owned()))
            .collect();
        let proven_range = BlockRange::from_block_number(transaction_to_prove[0].block_number);
        let proven_range_transactions =
            test_data::filter_transactions_for_block_ranges(&[proven_range], &transactions);

        let up_to_lower = all_block_ranges.keys().nth(1).unwrap().end;
        let up_to_higher = all_block_ranges.keys().last().unwrap().end;

        let mut transaction_retriever = MockTransactionsRetriever::new();
        transaction_retriever
            .expect_get_by_hashes()
            .returning(move |_, _| Ok(transaction_to_prove.clone()));
        transaction_retriever
            .expect_get_by_block_ranges()
            .returning(move |_| Ok(proven_range_transactions.clone()));

        let mut block_range_root_retriever = MockLegacyBlockRangeRootRetrieverImpl::new();
        block_range_root_retriever
            .expect_compute_merkle_map_from_block_range_roots()
            .returning(move |up_to| {
                let block_ranges = if up_to == up_to_lower {
                    lower_block_ranges.clone()
                } else {
                    all_block_ranges.clone()
                };
                Ok(test_data::compute_mk_map_from_block_ranges_map(
                    block_ranges,
                ))
            });

        let prover = LegacyMithrilProverService::<MKTreeStoreInMemory>::new(
            Arc::new(transaction_retriever),
            Arc::new(block_range_root_retriever),
            1,
            4,
            TestLogger::stdout(),
        );

        // Warm the higher tip first: a stale single-tip cache would then return the
        // higher tip's root when proving the lower tip.
        let proof_higher = prover
            .compute_transactions_proofs(up_to_higher, &transaction_hashes)
            .await
            .unwrap();
        let proof_lower = prover
            .compute_transactions_proofs(up_to_lower, &transaction_hashes)
            .await
            .unwrap();

        proof_higher[0].verify().unwrap();
        proof_lower[0].verify().unwrap();
        assert_ne!(
            proof_lower[0].merkle_root(),
            proof_higher[0].merkle_root(),
            "each tip must be proven against its own block-range-roots map"
        );

        // The same tip is reproducible regardless of which tips were proven before it.
        let proof_lower_again = prover
            .compute_transactions_proofs(up_to_lower, &transaction_hashes)
            .await
            .unwrap();
        assert_eq!(
            proof_lower[0].merkle_root(),
            proof_lower_again[0].merkle_root()
        );
    }
}
