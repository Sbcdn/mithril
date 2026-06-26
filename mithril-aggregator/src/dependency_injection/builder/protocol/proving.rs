use std::sync::Arc;

use mithril_common::crypto_helper::MKTreeStoreInMemory;

use crate::dependency_injection::{DependenciesBuilder, Result};
use crate::get_dependency;
use crate::services::{
    LegacyMithrilProverService, LegacyProverService, MithrilProverService, ProverService,
    TxTreeService,
};
impl DependenciesBuilder {
    /// Build the transaction-tree service (canonical per-range tree inputs).
    async fn build_tx_tree_service(&mut self) -> Result<Arc<TxTreeService>> {
        let signed_entity_service = self.get_signed_entity_service().await?;
        let chain_data_repository = self.get_chain_data_repository().await?;

        Ok(Arc::new(TxTreeService::new(
            signed_entity_service,
            chain_data_repository,
        )))
    }

    /// [TxTreeService] service
    pub async fn get_tx_tree_service(&mut self) -> Result<Arc<TxTreeService>> {
        get_dependency!(self.tx_tree_service)
    }

    /// Build Prover service
    pub async fn build_prover_service(&mut self) -> Result<Arc<dyn ProverService>> {
        #[cfg(feature = "prover-accumulator")]
        if self.configuration.cardano_transactions_prover_use_accumulator() {
            return self.build_accumulator_blocks_prover_service().await;
        }

        let mk_map_pool_size = self
            .configuration
            .cardano_blocks_transactions_prover_cache_pool_size();
        let transaction_retriever = self.get_chain_data_repository().await?;
        let block_range_root_retriever = self.get_chain_data_repository().await?;
        let logger = self.root_logger();
        let prover_service = MithrilProverService::<MKTreeStoreInMemory>::new(
            transaction_retriever,
            block_range_root_retriever,
            mk_map_pool_size,
            logger,
        );

        Ok(Arc::new(prover_service))
    }

    /// [ProverService] service
    pub async fn get_prover_service(&mut self) -> Result<Arc<dyn ProverService>> {
        get_dependency!(self.prover_service)
    }

    /// Build Legacy Prover service
    pub async fn build_legacy_prover_service(&mut self) -> Result<Arc<dyn LegacyProverService>> {
        #[cfg(feature = "prover-accumulator")]
        if self.configuration.cardano_transactions_prover_use_accumulator() {
            return self.build_accumulator_prover_service().await;
        }

        let mk_map_pool_size = self.configuration.cardano_transactions_prover_cache_pool_size();
        let transaction_retriever = self.get_chain_data_repository().await?;
        let block_range_root_retriever = self.get_chain_data_repository().await?;
        let logger = self.root_logger();
        let prover_service = LegacyMithrilProverService::<MKTreeStoreInMemory>::new(
            transaction_retriever,
            block_range_root_retriever,
            mk_map_pool_size,
            logger,
        );

        Ok(Arc::new(prover_service))
    }

    /// [LegacyProverService] service
    pub async fn get_legacy_prover_service(&mut self) -> Result<Arc<dyn LegacyProverService>> {
        get_dependency!(self.legacy_prover_service)
    }

    /// Build the MMR-accumulator-backed Legacy Prover service and warm it from the sealed
    /// block-range-roots.
    #[cfg(feature = "prover-accumulator")]
    async fn build_accumulator_prover_service(&mut self) -> Result<Arc<dyn LegacyProverService>> {
        use mithril_common::{
            crypto_helper::MKTreeStorer, entities::BlockNumber,
            signable_builder::LegacyBlockRangeRootRetriever,
        };

        use crate::services::{AccumulatorProverService, BlockRangeAccumulator, MKTreeStoreRedb};

        let transaction_retriever = self.get_chain_data_repository().await?;
        let block_range_root_retriever: Arc<dyn LegacyBlockRangeRootRetriever<MKTreeStoreRedb>> =
            self.get_chain_data_repository().await?;
        let logger = self.root_logger();

        let store =
            if self.configuration.data_stores_directory() == std::path::Path::new(":memory:") {
                // In-memory store for test/ephemeral configurations.
                MKTreeStoreRedb::build()?
            } else {
                let store_path = self
                    .configuration
                    .data_stores_directory()
                    .join("mktree-accumulator-v1.redb");
                MKTreeStoreRedb::open(&store_path)?
            };

        let accumulator = Arc::new(BlockRangeAccumulator::new(store, logger)?);

        // Warm the accumulator from the sealed block-range-roots at startup. The bound is
        // `i64::MAX`: the persistence query casts it to `i64`, so `u64::MAX` would wrap to `-1`.
        let block_range_roots = block_range_root_retriever
            .retrieve_block_range_roots(BlockNumber(i64::MAX as u64))
            .await?
            .collect::<Vec<_>>();
        accumulator.synchronize_with(block_range_roots).await?;

        Ok(Arc::new(AccumulatorProverService::new(
            transaction_retriever,
            block_range_root_retriever,
            accumulator,
        )))
    }

    /// Build the MMR-accumulator-backed v2 ([`ProverService`]) and warm it from the sealed
    /// CardanoBlocksTransactions block-range-roots.
    #[cfg(feature = "prover-accumulator")]
    async fn build_accumulator_blocks_prover_service(&mut self) -> Result<Arc<dyn ProverService>> {
        use mithril_common::{
            crypto_helper::MKTreeStorer, entities::BlockNumber,
            signable_builder::BlockRangeRootRetriever,
        };

        use crate::services::{
            AccumulatorBlocksProverService, BlockRangeAccumulator, MKTreeStoreRedb,
        };

        let blocks_transactions_retriever = self.get_chain_data_repository().await?;
        let block_range_root_retriever: Arc<dyn BlockRangeRootRetriever<MKTreeStoreRedb>> =
            self.get_chain_data_repository().await?;
        let logger = self.root_logger();

        let store =
            if self.configuration.data_stores_directory() == std::path::Path::new(":memory:") {
                MKTreeStoreRedb::build()?
            } else {
                let store_path = self
                    .configuration
                    .data_stores_directory()
                    .join("mktree-accumulator-v2.redb");
                MKTreeStoreRedb::open(&store_path)?
            };

        let accumulator = Arc::new(BlockRangeAccumulator::new(store, logger)?);

        let block_range_roots = block_range_root_retriever
            .retrieve_block_range_roots(BlockNumber(i64::MAX as u64))
            .await?
            .collect::<Vec<_>>();
        accumulator.synchronize_with(block_range_roots).await?;

        Ok(Arc::new(AccumulatorBlocksProverService::new(
            blocks_transactions_retriever,
            block_range_root_retriever,
            accumulator,
        )))
    }
}
