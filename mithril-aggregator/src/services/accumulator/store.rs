//! A `redb`-backed, append-only node store for the MMR accumulator prover.
//!
//! It holds the Merkle Mountain Range nodes (`position -> node bytes`) of the block-range-roots
//! accumulator on disk, so the tree's working set is paged off-RAM by the operating system instead
//! of staying resident. The accumulator rebuilds the store from the sealed block-range-roots on
//! each restart — it is an off-RAM working cache, not a source of truth reused across restarts — so
//! appends use [`Durability::Eventual`] to avoid an fsync per leaf, and obsolete nodes left behind
//! by a shrunk chain are inert (reads are bounded by the current MMR size). Only the node store is
//! required: the accumulator generates proofs with
//! [`MKTree::generate_proof_at_size`][mithril_common::crypto_helper::MKTree::generate_proof_at_size]
//! using explicit leaf positions, so the value -> position leaf index of
//! [`MKTreeLeafIndexer`] is intentionally **not** maintained (its methods are inert).

use std::{path::Path, sync::Arc};

use anyhow::Context;
use redb::{Database, Durability, TableDefinition};

use mithril_common::{
    StdResult,
    crypto_helper::{MKTreeLeafIndexer, MKTreeLeafPosition, MKTreeNode, MKTreeStorer},
};

/// `position -> node bytes` table holding the append-only MMR nodes.
const NODES_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("mk_node");

/// A `redb`-backed, append-only [`MKTreeStorer`] for the accumulator's master Merkle tree.
#[derive(Clone)]
pub struct MKTreeStoreRedb {
    database: Arc<Database>,
}

impl MKTreeStoreRedb {
    /// Open (creating it if needed) a node store at `path`.
    pub fn open(path: &Path) -> StdResult<Self> {
        let database = Database::create(path)
            .with_context(|| format!("Failed to open redb MKTree store at '{path:?}'"))?;
        let transaction = database.begin_write()?;
        {
            // Ensure the table exists so read transactions never fail on a fresh store.
            transaction.open_table(NODES_TABLE)?;
        }
        transaction.commit()?;

        Ok(Self {
            database: Arc::new(database),
        })
    }

    /// Remove all stored nodes (used to rebuild the accumulator from scratch).
    pub fn clear(&self) -> StdResult<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(NODES_TABLE)?;
            table.retain(|_, _| false)?;
        }
        transaction.commit()?;

        Ok(())
    }
}

impl MKTreeStorer for MKTreeStoreRedb {
    fn build() -> StdResult<Self> {
        // Required by the trait; the accumulator constructs instances via `open(path)`. Fall
        // back to a unique temporary file so a default-built instance is still usable.
        let path =
            std::env::temp_dir().join(format!("mithril-mktree-{}.redb", uuid::Uuid::new_v4()));
        Self::open(&path)
    }

    fn get_elem(&self, pos: u64) -> StdResult<Option<Arc<MKTreeNode>>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(NODES_TABLE)?;
        match table.get(pos)? {
            Some(value) => Ok(Some(Arc::new(MKTreeNode::new(value.value().to_vec())))),
            None => Ok(None),
        }
    }

    fn append(&self, pos: u64, elems: Vec<Arc<MKTreeNode>>) -> StdResult<()> {
        let mut transaction = self.database.begin_write()?;
        // The accumulator rebuilds this store from the sealed block-range-roots on every restart,
        // so per-commit durability is unnecessary. `Eventual` lets each append return without
        // waiting for an fsync (redb batches the flush and still frees pages), which avoids one
        // fsync per leaf when backfilling hundreds of thousands of ranges.
        transaction.set_durability(Durability::Eventual);
        {
            let mut table = transaction.open_table(NODES_TABLE)?;
            for (i, elem) in elems.into_iter().enumerate() {
                let node: &MKTreeNode = elem.as_ref();
                let bytes: &[u8] = node;
                table.insert(pos + i as u64, bytes)?;
            }
        }
        transaction.commit()?;

        Ok(())
    }
}

// The accumulator proves via explicit leaf positions, so the value -> position index is not
// kept. These methods are inert; the store must not be used for value-based proofs or cloning.
impl MKTreeLeafIndexer for MKTreeStoreRedb {
    fn set_leaf_position(&self, _pos: MKTreeLeafPosition, _node: Arc<MKTreeNode>) -> StdResult<()> {
        Ok(())
    }

    fn get_leaf_position(&self, _node: &MKTreeNode) -> Option<MKTreeLeafPosition> {
        None
    }

    fn total_leaves(&self) -> usize {
        0
    }

    fn leaves(&self) -> Vec<MKTreeNode> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::crypto_helper::{MKTree, MKTreeStoreInMemory};

    use super::*;

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mithril-mktree-test-{}.redb", uuid::Uuid::new_v4()))
    }

    #[test]
    fn building_a_tree_over_redb_matches_the_in_memory_root_and_survives_reopen() {
        let leaves: Vec<MKTreeNode> = (0..50).map(|i| format!("leaf-{i}").into()).collect();
        let expected_root = MKTree::<MKTreeStoreInMemory>::new(&leaves)
            .unwrap()
            .compute_root()
            .unwrap();

        let path = temp_path();
        let mmr_size = {
            let store = MKTreeStoreRedb::open(&path).unwrap();
            let mut tree = MKTree::from_storer_at_size(store, 0).unwrap();
            tree.append(&leaves).unwrap();
            assert_eq!(
                expected_root,
                tree.compute_root_at_size(leaves.len() as u64).unwrap()
            );
            ckb_size(leaves.len() as u64)
        };

        // Reopen the persisted store and reproduce the historical root without rebuilding.
        let reopened = MKTreeStoreRedb::open(&path).unwrap();
        let tree = MKTree::from_storer_at_size(reopened, mmr_size).unwrap();
        assert_eq!(
            expected_root,
            tree.compute_root_at_size(leaves.len() as u64).unwrap()
        );

        std::fs::remove_file(&path).ok();
    }

    // Mirror of ckb's leaf_index_to_mmr_size for the test (avoids exposing it from mithril-common).
    fn ckb_size(leaf_count: u64) -> u64 {
        2 * leaf_count - (leaf_count.count_ones() as u64)
    }
}
