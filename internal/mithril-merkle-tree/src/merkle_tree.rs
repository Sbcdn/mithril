use anyhow::{Context, anyhow};
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{
    Error as MMRError, MMR, MMRStoreReadOps, MMRStoreWriteOps, Merge, MerkleProof,
    Result as MMRResult, leaf_index_to_mmr_size, leaf_index_to_pos,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    ops::{Add, Deref},
    sync::{Arc, RwLock},
};

use crate::{StdError, StdResult};

/// Alias for a byte
pub type Bytes = Vec<u8>;

/// Alias for a Merkle tree leaf position
pub type MKTreeLeafPosition = u64;

/// A node of a Merkle tree
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Serialize, Deserialize)]
pub struct MKTreeNode {
    hash: Bytes,
}

impl MKTreeNode {
    /// MKTreeNode factory
    pub fn new(hash: Bytes) -> Self {
        Self { hash }
    }

    /// Create a MKTreeNode from a hex representation
    pub fn from_hex(hex: &str) -> StdResult<Self> {
        let hash = hex::decode(hex)?;
        Ok(Self { hash })
    }

    /// Create a hex representation of the MKTreeNode
    pub fn to_hex(&self) -> String {
        hex::encode(&self.hash)
    }
}

impl Deref for MKTreeNode {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.hash
    }
}

impl From<String> for MKTreeNode {
    fn from(other: String) -> Self {
        Self {
            hash: other.as_str().into(),
        }
    }
}

impl From<&String> for MKTreeNode {
    fn from(other: &String) -> Self {
        Self {
            hash: other.as_str().into(),
        }
    }
}

impl From<&str> for MKTreeNode {
    fn from(other: &str) -> Self {
        Self {
            hash: other.as_bytes().to_vec(),
        }
    }
}

impl<S: MKTreeStorer> TryFrom<MKTree<S>> for MKTreeNode {
    type Error = StdError;
    fn try_from(other: MKTree<S>) -> Result<Self, Self::Error> {
        other.compute_root()
    }
}

impl<S: MKTreeStorer> TryFrom<&MKTree<S>> for MKTreeNode {
    type Error = StdError;
    fn try_from(other: &MKTree<S>) -> Result<Self, Self::Error> {
        other.compute_root()
    }
}

impl Display for MKTreeNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.hash))
    }
}

impl Add for MKTreeNode {
    type Output = MKTreeNode;

    fn add(self, other: MKTreeNode) -> MKTreeNode {
        &self + &other
    }
}

impl Add for &MKTreeNode {
    type Output = MKTreeNode;

    fn add(self, other: &MKTreeNode) -> MKTreeNode {
        let mut hasher = Blake2s256::new();
        hasher.update(self.deref());
        hasher.update(other.deref());
        let hash_merge = hasher.finalize();
        MKTreeNode::new(hash_merge.to_vec())
    }
}

struct MergeMKTreeNode {}

impl Merge for MergeMKTreeNode {
    type Item = Arc<MKTreeNode>;

    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> MMRResult<Self::Item> {
        Ok(Arc::new((**lhs).clone() + (**rhs).clone()))
    }
}

/// A Merkle proof
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MKProof {
    inner_root: Arc<MKTreeNode>,
    inner_leaves: Vec<(MKTreeLeafPosition, Arc<MKTreeNode>)>,
    inner_proof_size: u64,
    inner_proof_items: Vec<Arc<MKTreeNode>>,
}

impl MKProof {
    /// Return a reference to its merkle root.
    pub fn root(&self) -> &MKTreeNode {
        &self.inner_root
    }

    /// Verification of a Merkle proof
    pub fn verify(&self) -> StdResult<()> {
        MerkleProof::<Arc<MKTreeNode>, MergeMKTreeNode>::new(
            self.inner_proof_size,
            self.inner_proof_items.clone(),
        )
        .verify(self.inner_root.to_owned(), self.inner_leaves.to_owned())?
        .then_some(())
        .with_context(|| "Invalid MKProof")
    }

    /// Check if the proof contains the given leaves
    pub fn contains(&self, leaves: &[MKTreeNode]) -> StdResult<()> {
        leaves
            .iter()
            .all(|leaf| self.inner_leaves.iter().any(|(_, l)| l.deref() == leaf))
            .then_some(())
            .with_context(|| "Leaves not found in the MKProof")
    }

    /// List the leaves of the proof
    pub fn leaves(&self) -> Vec<MKTreeNode> {
        self.inner_leaves
            .iter()
            .map(|(_, l)| (**l).clone())
            .collect::<Vec<_>>()
    }

    /// Convert the proof to bytes
    pub fn to_bytes(&self) -> StdResult<Bytes> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map_err(|e| e.into())
    }

    /// Convert the proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> StdResult<Self> {
        let (res, _) =
            bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())?;

        Ok(res)
    }
}

impl From<MKProof> for MKTreeNode {
    fn from(other: MKProof) -> Self {
        other.root().to_owned()
    }
}

/// A Merkle tree store in memory
#[derive(Clone)]
pub struct MKTreeStoreInMemory {
    inner_leaves: Arc<RwLock<HashMap<Arc<MKTreeNode>, MKTreeLeafPosition>>>,
    inner_store: Arc<RwLock<HashMap<u64, Arc<MKTreeNode>>>>,
}

impl MKTreeStoreInMemory {
    fn new() -> Self {
        Self {
            inner_leaves: Arc::new(RwLock::new(HashMap::new())),
            inner_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl MKTreeLeafIndexer for MKTreeStoreInMemory {
    fn set_leaf_position(&self, pos: MKTreeLeafPosition, node: Arc<MKTreeNode>) -> StdResult<()> {
        let mut inner_leaves = self.inner_leaves.write().unwrap();
        (*inner_leaves).insert(node, pos);

        Ok(())
    }

    fn get_leaf_position(&self, node: &MKTreeNode) -> Option<MKTreeLeafPosition> {
        let inner_leaves = self.inner_leaves.read().unwrap();
        (*inner_leaves).get(node).cloned()
    }

    fn total_leaves(&self) -> usize {
        let inner_leaves = self.inner_leaves.read().unwrap();
        (*inner_leaves).len()
    }

    fn leaves(&self) -> Vec<MKTreeNode> {
        let inner_leaves = self.inner_leaves.read().unwrap();
        (*inner_leaves)
            .iter()
            .map(|(leaf, position)| (position, leaf))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .map(|leaf| (**leaf).clone())
            .collect()
    }
}

impl MKTreeStorer for MKTreeStoreInMemory {
    fn build() -> StdResult<Self> {
        Ok(Self::new())
    }

    fn get_elem(&self, pos: u64) -> StdResult<Option<Arc<MKTreeNode>>> {
        let inner_store = self.inner_store.read().unwrap();

        Ok((*inner_store).get(&pos).cloned())
    }

    fn append(&self, pos: u64, elems: Vec<Arc<MKTreeNode>>) -> StdResult<()> {
        let mut inner_store = self.inner_store.write().unwrap();
        for (i, elem) in elems.into_iter().enumerate() {
            (*inner_store).insert(pos + i as u64, elem);
        }

        Ok(())
    }
}

/// The Merkle tree storer trait
pub trait MKTreeStorer: Clone + Send + Sync + MKTreeLeafIndexer {
    /// Try to create a new instance of the storer
    fn build() -> StdResult<Self>;

    /// Get the element at the given position
    fn get_elem(&self, pos: u64) -> StdResult<Option<Arc<MKTreeNode>>>;

    /// Append elements at the given position
    fn append(&self, pos: u64, elems: Vec<Arc<MKTreeNode>>) -> StdResult<()>;
}

/// This struct exists only to implement for a [MkTreeStore] the [MMRStoreReadOps] and
/// [MMRStoreWriteOps] from merkle_mountain_range crate without the need to reexport types
/// from that crate.
///
/// Rust don't allow the following:
/// ```ignore
/// impl<S: MKTreeStorer> MMRStoreReadOps<Arc<MKTreeNode>> for S {}
/// ```
/// Since it disallows implementations of traits for arbitrary types which are not defined in
/// the same crate as the trait itself (see [E0117](https://doc.rust-lang.org/error_codes/E0117.html)).
struct MKTreeStore<S: MKTreeStorer> {
    storer: Box<S>,
}

impl<S: MKTreeStorer> MKTreeStore<S> {
    fn build() -> StdResult<Self> {
        let storer = Box::new(S::build()?);
        Ok(Self { storer })
    }

    /// Mount a store over an already-existing storer instance, without creating a new one.
    fn build_from(storer: S) -> Self {
        Self {
            storer: Box::new(storer),
        }
    }
}

impl<S: MKTreeStorer> MMRStoreReadOps<Arc<MKTreeNode>> for MKTreeStore<S> {
    fn get_elem(&self, pos: u64) -> MMRResult<Option<Arc<MKTreeNode>>> {
        self.storer
            .get_elem(pos)
            .map_err(|e| MMRError::StoreError(e.to_string()))
    }
}

impl<S: MKTreeStorer> MMRStoreWriteOps<Arc<MKTreeNode>> for MKTreeStore<S> {
    fn append(&mut self, pos: u64, elems: Vec<Arc<MKTreeNode>>) -> MMRResult<()> {
        self.storer
            .append(pos, elems)
            .map_err(|e| MMRError::StoreError(e.to_string()))
    }
}

impl<S: MKTreeStorer> MKTreeLeafIndexer for MKTreeStore<S> {
    fn set_leaf_position(&self, pos: MKTreeLeafPosition, leaf: Arc<MKTreeNode>) -> StdResult<()> {
        self.storer.set_leaf_position(pos, leaf)
    }

    fn get_leaf_position(&self, leaf: &MKTreeNode) -> Option<MKTreeLeafPosition> {
        self.storer.get_leaf_position(leaf)
    }

    fn total_leaves(&self) -> usize {
        self.storer.total_leaves()
    }

    fn leaves(&self) -> Vec<MKTreeNode> {
        self.storer.leaves()
    }
}

/// The Merkle tree leaves indexer trait
pub trait MKTreeLeafIndexer {
    /// Get the position of the leaf in the Merkle tree
    fn set_leaf_position(&self, pos: MKTreeLeafPosition, leaf: Arc<MKTreeNode>) -> StdResult<()>;

    /// Get the position of the leaf in the Merkle tree
    fn get_leaf_position(&self, leaf: &MKTreeNode) -> Option<MKTreeLeafPosition>;

    /// Number of leaves in the Merkle tree
    fn total_leaves(&self) -> usize;

    /// List of leaves with their positions in the Merkle tree
    fn leaves(&self) -> Vec<MKTreeNode>;

    /// Check if the Merkle tree contains the given leaf
    fn contains_leaf(&self, leaf: &MKTreeNode) -> bool {
        self.get_leaf_position(leaf).is_some()
    }
}

/// A Merkle tree
pub struct MKTree<S: MKTreeStorer> {
    inner_tree: MMR<Arc<MKTreeNode>, MergeMKTreeNode, MKTreeStore<S>>,
}

impl<S: MKTreeStorer> MKTree<S> {
    /// MKTree factory
    pub fn new<T: Into<MKTreeNode> + Clone>(leaves: &[T]) -> StdResult<Self> {
        Self::new_from_iter(leaves.iter().cloned())
    }

    /// MKTree factory
    pub fn new_from_iter<T: IntoIterator<Item = U>, U: Into<MKTreeNode>>(
        leaves: T,
    ) -> StdResult<Self> {
        let mut inner_tree = MMR::<_, _, _>::new(0, MKTreeStore::<S>::build()?);
        for leaf in leaves.into_iter() {
            let leaf = Arc::new(leaf.into());
            let inner_tree_position = inner_tree.push(leaf.clone())?;
            inner_tree
                .store()
                .set_leaf_position(inner_tree_position, leaf.clone())?;
        }
        inner_tree.commit()?;

        Ok(Self { inner_tree })
    }

    /// Append leaves to the Merkle tree
    pub fn append<T: Into<MKTreeNode> + Clone>(&mut self, leaves: &[T]) -> StdResult<()> {
        for leaf in leaves {
            let leaf = Arc::new(leaf.to_owned().into());
            let inner_tree_position = self.inner_tree.push(leaf.clone())?;
            self.inner_tree
                .store()
                .set_leaf_position(inner_tree_position, leaf.clone())?;
        }
        self.inner_tree.commit()?;

        Ok(())
    }

    /// Number of leaves in the Merkle tree
    pub fn total_leaves(&self) -> usize {
        self.inner_tree.store().total_leaves()
    }

    /// List of leaves with their positions in the Merkle tree
    pub fn leaves(&self) -> Vec<MKTreeNode> {
        self.inner_tree.store().leaves()
    }

    /// Check if the Merkle tree contains the given leaf
    pub fn contains(&self, leaf: &MKTreeNode) -> bool {
        self.inner_tree.store().contains_leaf(leaf)
    }

    /// Generate root of the Merkle tree
    pub fn compute_root(&self) -> StdResult<MKTreeNode> {
        Ok((*self
            .inner_tree
            .get_root()
            .with_context(|| "Could not compute Merkle Tree root")?)
        .clone())
    }

    /// Generate Merkle proof of memberships in the tree
    pub fn compute_proof(&self, leaves: &[MKTreeNode]) -> StdResult<MKProof> {
        let inner_leaves = leaves
            .iter()
            .map(|leaf| {
                if let Some(leaf_position) = self.inner_tree.store().get_leaf_position(leaf) {
                    Ok((leaf_position, Arc::new(leaf.to_owned())))
                } else {
                    Err(anyhow!("Leaf not found in the Merkle tree"))
                }
            })
            .collect::<StdResult<Vec<_>>>()?;
        let proof = self.inner_tree.gen_proof(
            inner_leaves
                .iter()
                .map(|(leaf_position, _leaf)| *leaf_position)
                .collect(),
        )?;
        Ok(MKProof {
            inner_root: Arc::new(self.compute_root()?),
            inner_leaves,
            inner_proof_size: proof.mmr_size(),
            inner_proof_items: proof.proof_items().to_vec(),
        })
    }

    /// Mount a Merkle tree over an existing storer at a known MMR size.
    ///
    /// Unlike [`new_from_iter`][Self::new_from_iter], this does **not** rebuild the tree by
    /// pushing leaves: it wraps a storer that already holds the tree's nodes (for instance a
    /// persistent store reloaded on startup) at `mmr_size`. Use `0` for an empty store and then
    /// [`append`][Self::append]. Combined with [`generate_proof_at_size`][Self::generate_proof_at_size],
    /// this lets a single append-only tree serve proofs against any of its past sizes.
    ///
    /// # Leaf-index caveat
    ///
    /// A mounted tree carries the node store but **not** the leaf-position index that
    /// [`new_from_iter`][Self::new_from_iter] builds, so operations that read that index see only
    /// the leaves subsequently [`append`][Self::append]ed, not the mounted ones:
    /// [`leaves`][Self::leaves], [`total_leaves`][Self::total_leaves], [`contains`][Self::contains],
    /// and — because it rebuilds from `leaves()` — `clone()`. Use a mounted tree only for
    /// size-anchored root/proof generation ([`compute_root_at_size`][Self::compute_root_at_size],
    /// [`generate_proof_at_size`][Self::generate_proof_at_size]) and [`append`][Self::append]; do
    /// not clone it or rely on its leaf accessors.
    pub fn from_storer_at_size(storer: S, mmr_size: u64) -> StdResult<Self> {
        let inner_tree = MMR::<_, _, _>::new(mmr_size, MKTreeStore::<S>::build_from(storer));
        // Fail fast if the storer is inconsistent with `mmr_size`: a non-empty tree must be able to
        // bag its peaks, so a missing or mismatched node surfaces here instead of silently
        // producing wrong roots and proofs later.
        if mmr_size > 0 {
            inner_tree.get_root().with_context(|| {
                format!("Storer is not consistent with the requested MMR size {mmr_size}")
            })?;
        }

        Ok(Self { inner_tree })
    }

    /// Compute the root the tree had when it contained exactly `leaf_count` leaves.
    ///
    /// The tree is an append-only Merkle Mountain Range, so an earlier root is reproduced by
    /// bagging the peaks of the historical size; no rebuild and no extra storage are required.
    pub fn compute_root_at_size(&self, leaf_count: u64) -> StdResult<MKTreeNode> {
        if leaf_count == 0 {
            return Err(anyhow!(
                "Could not compute Merkle Tree root for an empty size"
            ));
        }
        let view = self.view_at_size(leaf_count);

        Ok((*view
            .get_root()
            .with_context(|| format!("Could not compute Merkle Tree root at size {leaf_count}"))?)
        .clone())
    }

    /// Generate a membership proof against a past size of this append-only tree.
    ///
    /// `leaf_count` is the number of leaves the tree had at the target size, and `leaves` are the
    /// `(leaf_index, leaf_value)` pairs to prove, where `leaf_index` is the 0-based ordinal of the
    /// leaf (each must be `< leaf_count`). The resulting [`MKProof`] verifies against
    /// [`compute_root_at_size(leaf_count)`][Self::compute_root_at_size] and is identical to the
    /// proof the tree would have produced when it held exactly `leaf_count` leaves.
    ///
    /// The caller owns the leaf-index bookkeeping, which avoids relying on the in-store
    /// leaf-position index that a reloaded persistent store may not carry.
    pub fn generate_proof_at_size(
        &self,
        leaf_count: u64,
        leaves: &[(u64, MKTreeNode)],
    ) -> StdResult<MKProof> {
        if leaf_count == 0 {
            return Err(anyhow!("Could not compute Merkle proof for an empty size"));
        }
        let inner_leaves = leaves
            .iter()
            .map(|(leaf_index, leaf)| (leaf_index_to_pos(*leaf_index), Arc::new(leaf.to_owned())))
            .collect::<Vec<_>>();
        let view = self.view_at_size(leaf_count);
        let proof = view.gen_proof(inner_leaves.iter().map(|(pos, _)| *pos).collect())?;
        let inner_root = view
            .get_root()
            .with_context(|| format!("Could not compute Merkle Tree root at size {leaf_count}"))?;

        Ok(MKProof {
            inner_root,
            inner_leaves,
            inner_proof_size: proof.mmr_size(),
            inner_proof_items: proof.proof_items().to_vec(),
        })
    }

    /// Open a read-only MMR view of this tree at the size it had with `leaf_count` leaves.
    ///
    /// The view shares the same storer (internal nodes are immutable once written), so reading
    /// an earlier size never depends on nodes appended afterwards.
    fn view_at_size(
        &self,
        leaf_count: u64,
    ) -> MMR<Arc<MKTreeNode>, MergeMKTreeNode, MKTreeStore<S>> {
        let mmr_size = leaf_index_to_mmr_size(leaf_count - 1);
        let storer = self.inner_tree.store().storer.as_ref().clone();

        MMR::new(mmr_size, MKTreeStore::build_from(storer))
    }
}

impl<S: MKTreeStorer> Clone for MKTree<S> {
    fn clone(&self) -> Self {
        // Rebuilds an independent tree from the leaf-position index. A tree mounted via
        // `from_storer_at_size` does not populate that index, so it clones to an empty tree — see
        // the leaf-index caveat there; such trees must not be cloned. (A store-level clone is not
        // an option: an in-memory storer shares its state behind an `Arc`, so it would not be
        // independent.)
        // Cloning should never fail so unwrap is safe
        Self::new(&self.leaves()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::test::MKProofTestExtension;

    use super::*;

    fn generate_leaves(total_leaves: usize) -> Vec<MKTreeNode> {
        (0..total_leaves).map(|i| format!("test-{i}").into()).collect()
    }

    #[test]
    fn generate_proof_at_size_reproduces_a_past_proof_byte_for_byte() {
        // For an append-only tree grown to `total` leaves, proving leaves against a past size
        // `n` must produce the exact same proof bytes and root as a tree built with only the
        // first `n` leaves. Covers single-leaf, multi-peak, single-peak and current-size cases.
        let cases: &[(usize, u64, &[u64])] = &[
            (9, 5, &[0, 2, 4]), // n=5 (0b101) -> 2 peaks, grown by 4
            (9, 1, &[0]),       // single-leaf historical size
            (9, 3, &[1, 2]),    // n=3 (0b11)  -> 2 peaks
            (9, 4, &[0, 3]),    // n=4 (0b100) -> single peak
            (16, 9, &[0, 8]),   // proving the last leaf of the historical size
            (5, 5, &[2]),       // historical size == current size
        ];

        for &(total, n, indices) in cases {
            let leaves = generate_leaves(total);
            // Tree grown to `total` leaves over its store.
            let full = MKTree::<MKTreeStoreInMemory>::new(&leaves).unwrap();
            // Reference tree containing exactly the first `n` leaves.
            let reference = MKTree::<MKTreeStoreInMemory>::new(&leaves[..n as usize]).unwrap();

            let values: Vec<MKTreeNode> =
                indices.iter().map(|&i| leaves[i as usize].to_owned()).collect();
            let reference_proof = reference.compute_proof(&values).unwrap();

            let indexed: Vec<(u64, MKTreeNode)> =
                indices.iter().map(|&i| (i, leaves[i as usize].to_owned())).collect();
            let view_proof = full.generate_proof_at_size(n, &indexed).unwrap();

            assert_eq!(
                reference_proof.to_bytes().unwrap(),
                view_proof.to_bytes().unwrap(),
                "proof bytes differ for total={total}, n={n}, indices={indices:?}"
            );
            assert_eq!(
                reference.compute_root().unwrap(),
                full.compute_root_at_size(n).unwrap(),
                "root differs for total={total}, n={n}"
            );
            view_proof.verify().unwrap();
        }
    }

    #[test]
    fn from_storer_at_size_then_append_matches_a_fresh_build() {
        let leaves = generate_leaves(7);
        let expected = MKTree::<MKTreeStoreInMemory>::new(&leaves).unwrap();

        let mut tree = MKTree::<MKTreeStoreInMemory>::from_storer_at_size(
            MKTreeStoreInMemory::build().unwrap(),
            0,
        )
        .unwrap();
        tree.append(&leaves).unwrap();

        assert_eq!(
            expected.compute_root().unwrap(),
            tree.compute_root().unwrap()
        );
    }

    #[test]
    fn from_storer_at_size_rejects_a_storer_inconsistent_with_the_size() {
        // An empty store cannot back a tree of size 3: the mount must fail fast rather than yield a
        // tree that would silently produce wrong roots and proofs.
        let result = MKTree::<MKTreeStoreInMemory>::from_storer_at_size(
            MKTreeStoreInMemory::build().unwrap(),
            3,
        );

        assert!(result.is_err());
    }

    #[test]
    fn historical_size_helpers_reject_an_empty_size() {
        let full = MKTree::<MKTreeStoreInMemory>::new(&generate_leaves(3)).unwrap();

        full.generate_proof_at_size(0, &[])
            .expect_err("empty size should be rejected");
        full.compute_root_at_size(0)
            .expect_err("empty size should be rejected");
    }

    #[test]
    fn golden_merkle_root() {
        let leaves = vec!["golden-1", "golden-2", "golden-3", "golden-4", "golden-5"];
        let mktree =
            MKTree::<MKTreeStoreInMemory>::new(&leaves).expect("MKTree creation should not fail");
        let mkroot = mktree.compute_root().expect("MKRoot generation should not fail");

        assert_eq!(
            "3bbced153528697ecde7345a22e50115306478353619411523e804f2323fd921",
            mkroot.to_hex()
        );
    }

    #[test]
    fn should_accept_valid_proof_generated_by_merkle_tree() {
        let leaves = generate_leaves(10);
        let leaves_to_verify = &[leaves[0].to_owned(), leaves[3].to_owned()];
        let proof =
            MKProof::from_leaves(leaves_to_verify).expect("MKProof generation should not fail");
        proof.verify().expect("The MKProof should be valid");
    }

    #[test]
    fn should_serialize_deserialize_proof() {
        let leaves = generate_leaves(10);
        let leaves_to_verify = &[leaves[0].to_owned(), leaves[3].to_owned()];
        let proof =
            MKProof::from_leaves(leaves_to_verify).expect("MKProof generation should not fail");

        let serialized_proof = proof.to_bytes().expect("Serialization should not fail");
        let deserialized_proof =
            MKProof::from_bytes(&serialized_proof).expect("Deserialization should not fail");
        assert_eq!(
            proof, deserialized_proof,
            "Deserialized proof should match the original"
        );
    }

    #[test]
    fn should_reject_invalid_proof_generated_by_merkle_tree() {
        let leaves = generate_leaves(10);
        let leaves_to_verify = &[leaves[0].to_owned(), leaves[3].to_owned()];
        let mut proof =
            MKProof::from_leaves(leaves_to_verify).expect("MKProof generation should not fail");
        proof.inner_root = Arc::new(leaves[1].to_owned());
        proof.verify().expect_err("The MKProof should be invalid");
    }

    #[test]
    fn should_list_leaves() {
        let leaves: Vec<MKTreeNode> = vec!["test-0".into(), "test-1".into(), "test-2".into()];
        let mktree =
            MKTree::<MKTreeStoreInMemory>::new(&leaves).expect("MKTree creation should not fail");
        let leaves_retrieved = mktree.leaves();

        assert_eq!(
            leaves.iter().collect::<Vec<_>>(),
            leaves_retrieved.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn should_clone_and_compute_same_root() {
        let leaves = generate_leaves(10);
        let mktree =
            MKTree::<MKTreeStoreInMemory>::new(&leaves).expect("MKTree creation should not fail");
        let mktree_clone = mktree.clone();

        assert_eq!(
            mktree.compute_root().unwrap(),
            mktree_clone.compute_root().unwrap(),
        );
    }

    #[test]
    fn should_support_append_leaves() {
        let leaves = generate_leaves(10);
        let leaves_creation = &leaves[..9];
        let leaves_to_append = &leaves[9..];
        let mut mktree = MKTree::<MKTreeStoreInMemory>::new(leaves_creation)
            .expect("MKTree creation should not fail");
        mktree
            .append(leaves_to_append)
            .expect("MKTree append leaves should not fail");

        assert_eq!(10, mktree.total_leaves());
    }

    #[test]
    fn tree_node_from_to_string() {
        let expected_str = "my_string";
        let expected_string = expected_str.to_string();
        let node_str: MKTreeNode = expected_str.into();
        let node_string: MKTreeNode = expected_string.clone().into();

        assert_eq!(node_str.to_string(), expected_str);
        assert_eq!(node_string.to_string(), expected_string);
    }

    #[test]
    fn contains_leaves() {
        let mut leaves_to_verify = generate_leaves(10);
        let leaves_not_verified = leaves_to_verify.drain(3..6).collect::<Vec<_>>();
        let proof =
            MKProof::from_leaves(&leaves_to_verify).expect("MKProof generation should not fail");

        // contains everything
        proof.contains(&leaves_to_verify).unwrap();

        // contains subpart
        proof.contains(&leaves_to_verify[0..2]).unwrap();

        // don't contains all not verified
        proof.contains(&leaves_not_verified).unwrap_err();

        // don't contains subpart of not verified
        proof.contains(&leaves_not_verified[1..2]).unwrap_err();

        // fail if part verified and part unverified
        proof
            .contains(&[leaves_to_verify[2].to_owned(), leaves_not_verified[0].to_owned()])
            .unwrap_err();
    }

    #[test]
    fn list_leaves() {
        let leaves_to_verify = generate_leaves(10);
        let proof =
            MKProof::from_leaves(&leaves_to_verify).expect("MKProof generation should not fail");

        let proof_leaves = proof.leaves();
        assert_eq!(proof_leaves, leaves_to_verify);
    }
}
