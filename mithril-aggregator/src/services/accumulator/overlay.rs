//! A copy-on-write overlay storer used to serve v2 proofs against a partial trailing block range.
//!
//! When a v2 (`CardanoBlocksTransactions`) tip falls inside a block range, the rebuild path adds a
//! transient *partial* leaf for that range on top of the sealed ones, which changes the master
//! tree's size. The accumulator only persists the sealed ranges, so to reproduce that master tree
//! it wraps the persistent store in this overlay: reads fall through to the persistent base, while
//! the partial leaf and the internal nodes created by appending it are kept in memory and dropped
//! with the overlay. The base store is never mutated.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use mithril_common::{
    StdResult,
    crypto_helper::{MKTreeLeafIndexer, MKTreeLeafPosition, MKTreeNode, MKTreeStorer},
};

/// A storer that overlays in-memory writes on top of a base storer, leaving the base untouched.
#[derive(Clone)]
pub struct OverlayStorer<S: MKTreeStorer> {
    base: S,
    overlay: Arc<RwLock<HashMap<u64, Arc<MKTreeNode>>>>,
}

impl<S: MKTreeStorer> OverlayStorer<S> {
    /// Create an overlay over `base`.
    pub fn new(base: S) -> Self {
        Self {
            base,
            overlay: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<S: MKTreeStorer> MKTreeStorer for OverlayStorer<S> {
    fn build() -> StdResult<Self> {
        Ok(Self::new(S::build()?))
    }

    fn get_elem(&self, pos: u64) -> StdResult<Option<Arc<MKTreeNode>>> {
        if let Some(node) = self.overlay.read().unwrap().get(&pos).cloned() {
            return Ok(Some(node));
        }
        self.base.get_elem(pos)
    }

    fn append(&self, pos: u64, elems: Vec<Arc<MKTreeNode>>) -> StdResult<()> {
        let mut overlay = self.overlay.write().unwrap();
        for (i, elem) in elems.into_iter().enumerate() {
            overlay.insert(pos + i as u64, elem);
        }

        Ok(())
    }
}

// The accumulator proves via explicit leaf positions, so the value -> position index is inert.
impl<S: MKTreeStorer> MKTreeLeafIndexer for OverlayStorer<S> {
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
