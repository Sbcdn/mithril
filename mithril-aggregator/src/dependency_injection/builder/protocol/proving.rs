use std::sync::Arc;

use mithril_common::{
    crypto_helper::{MKTreeStoreInMemory, MKTreeStorer},
    signable_builder::{BlockRangeRootRetriever, LegacyBlockRangeRootRetriever},
};

use crate::dependency_injection::{DependenciesBuilder, Result};
use crate::get_dependency;
use crate::services::{
    AccumulatorBlocksProverService, AccumulatorProverService, BlockRangeAccumulator,
    LegacyProverService, ProverService, TxTreeService,
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

    /// Build the v2 ([`ProverService`]) prover.
    ///
    /// Both transaction-proof provers are backed by the append-only block-range-roots accumulator,
    /// which serves an inclusion proof against any historical certified tip from a single tree
    /// (the master root at a past size is reproduced from the immutable MMR nodes). The default
    /// build keeps the accumulator in memory; enabling the `prover-accumulator` feature together
    /// with `cardano_transactions_prover_use_accumulator` backs it with an off-RAM redb store
    /// instead (rebuilt from the sealed block-range-roots on each restart).
    pub async fn build_prover_service(&mut self) -> Result<Arc<dyn ProverService>> {
        #[cfg(feature = "prover-accumulator")]
        if self.configuration.cardano_transactions_prover_use_accumulator() {
            let store = self.build_accumulator_redb_store("mktree-accumulator-v2.redb")?;
            return self.build_blocks_prover_service(store).await;
        }

        self.build_blocks_prover_service(MKTreeStoreInMemory::build()?)
            .await
    }

    /// [ProverService] service
    pub async fn get_prover_service(&mut self) -> Result<Arc<dyn ProverService>> {
        get_dependency!(self.prover_service)
    }

    /// Build the v1 ([`LegacyProverService`]) prover. See [`build_prover_service`] for how the
    /// accumulator backs both provers and how persistence is selected.
    ///
    /// [`build_prover_service`]: Self::build_prover_service
    pub async fn build_legacy_prover_service(&mut self) -> Result<Arc<dyn LegacyProverService>> {
        #[cfg(feature = "prover-accumulator")]
        if self.configuration.cardano_transactions_prover_use_accumulator() {
            let store = self.build_accumulator_redb_store("mktree-accumulator-v1.redb")?;
            return self.build_transactions_prover_service(store).await;
        }

        self.build_transactions_prover_service(MKTreeStoreInMemory::build()?)
            .await
    }

    /// [LegacyProverService] service
    pub async fn get_legacy_prover_service(&mut self) -> Result<Arc<dyn LegacyProverService>> {
        get_dependency!(self.legacy_prover_service)
    }

    /// Build the v1 accumulator-backed prover over `store`.
    ///
    /// The accumulator is created empty and synchronizes itself from the sealed block-range-roots
    /// on first use and on every `compute_cache`, so construction does not depend on the
    /// transaction store being populated (or even migrated) yet.
    async fn build_transactions_prover_service<S: MKTreeStorer + 'static>(
        &mut self,
        store: S,
    ) -> Result<Arc<dyn LegacyProverService>> {
        let transaction_retriever = self.get_chain_data_repository().await?;
        let block_range_root_retriever: Arc<dyn LegacyBlockRangeRootRetriever<S>> =
            self.get_chain_data_repository().await?;
        let accumulator = Arc::new(BlockRangeAccumulator::new(store, self.root_logger())?);

        Ok(Arc::new(AccumulatorProverService::new(
            transaction_retriever,
            block_range_root_retriever,
            accumulator,
        )))
    }

    /// Build the v2 accumulator-backed prover over `store`. Synchronizes lazily, like the v1 prover.
    async fn build_blocks_prover_service<S: MKTreeStorer + 'static>(
        &mut self,
        store: S,
    ) -> Result<Arc<dyn ProverService>> {
        let blocks_transactions_retriever = self.get_chain_data_repository().await?;
        let block_range_root_retriever: Arc<dyn BlockRangeRootRetriever<S>> =
            self.get_chain_data_repository().await?;
        let accumulator = Arc::new(BlockRangeAccumulator::new(store, self.root_logger())?);

        Ok(Arc::new(AccumulatorBlocksProverService::new(
            blocks_transactions_retriever,
            block_range_root_retriever,
            accumulator,
        )))
    }

    /// Open (or create) the redb store backing the persistent accumulator.
    #[cfg(feature = "prover-accumulator")]
    fn build_accumulator_redb_store(
        &self,
        file_name: &str,
    ) -> Result<crate::services::MKTreeStoreRedb> {
        use crate::services::MKTreeStoreRedb;

        let store = if self.configuration.data_stores_directory() == std::path::Path::new(":memory:")
        {
            // In-memory store for test/ephemeral configurations.
            MKTreeStoreRedb::build()?
        } else {
            let store_path = self.configuration.data_stores_directory().join(file_name);
            MKTreeStoreRedb::open(&store_path)?
        };

        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::ServeCommandConfiguration;
    use crate::dependency_injection::DependenciesBuilder;

    /// The default build must wire the accumulator-backed transaction provers.
    ///
    /// Both `build_legacy_prover_service` and `build_prover_service` are exercised while assembling
    /// the serve container; this guards their wiring (generic store plumbing, retriever coercions,
    /// lazy-synchronizing accumulator construction) against runtime regressions. The accumulator
    /// serves an inclusion proof against any historical certified tip from a single append-only
    /// tree — the previous default proved every request against the latest-tip Merkle map, so a
    /// proof requested for an older tip was computed against the wrong root and failed client
    /// verification. Byte-for-byte historical correctness against the rebuild path is covered by the
    /// accumulator differential tests in [`crate::services`].
    #[tokio::test]
    async fn default_build_wires_accumulator_backed_provers() {
        let config = ServeCommandConfiguration::new_sample(mithril_common::temp_dir!());
        let mut builder = DependenciesBuilder::new_with_stdout_logger(Arc::new(config));

        builder
            .build_serve_dependencies_container()
            .await
            .expect("the default build must wire the accumulator-backed transaction provers");
    }
}
