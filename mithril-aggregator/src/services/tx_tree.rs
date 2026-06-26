//! # Transaction-tree service
//!
//! Exposes the *canonical* per-block-range inputs of Mithril's Cardano-transaction Merkle tree
//! (the exact ordered leaves Mithril hashes) plus the `block_range_root`, resolved against a chosen
//! historical certificate (`up_to_block_number`, same at-or-below resolution as the proof route).
//!
//! It is a read-only, source-of-truth surface for external tools that rebuild the tree
//! independently: the ordering is taken straight from the production retrievers (no re-sorting), and
//! each range response recomputes its `block_range_root` from the returned leaves as a fidelity
//! guard. It computes nothing SHA-256/Plutus-side — only the canonical Blake2s inputs + roots.

use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use mithril_cardano_node_chain::chain_importer::ChainDataStore;
use mithril_common::StdResult;
use mithril_common::crypto_helper::{MKTree, MKTreeStoreInMemory};
use mithril_common::entities::{BlockNumber, BlockRange, CardanoBlockTransactionMkTreeNode};

use crate::database::repository::AggregatorCardanoChainDataRepository;
use crate::services::SignedEntityService;

/// Which transaction-tree protocol the inputs belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxTreeVersion {
    /// v1 `CardanoTransactions` (leaves = transaction hashes).
    V1,
    /// v2 `CardanoBlocksTransactions` (leaves = interleaved Block + Tx nodes).
    V2,
}

impl TxTreeVersion {
    /// Parse the `version` query parameter.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }
}

/// A single v2 leaf node, raw values; clients apply the leaf byte-format from the conventions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TxTreeNodeMessage {
    /// `Block/{block_hash}/{block_number}/{slot_number}`
    Block {
        /// Block hash (hex).
        block_hash: String,
        /// Block number.
        block_number: u64,
        /// Slot number.
        slot_number: u64,
    },
    /// `Tx/{transaction_hash}/{block_hash}/{block_number}/{slot_number}`
    Tx {
        /// Transaction hash (hex).
        transaction_hash: String,
        /// Hash of the block containing the transaction (hex).
        block_hash: String,
        /// Block number.
        block_number: u64,
        /// Slot number.
        slot_number: u64,
    },
}

impl From<CardanoBlockTransactionMkTreeNode> for TxTreeNodeMessage {
    fn from(node: CardanoBlockTransactionMkTreeNode) -> Self {
        match node {
            CardanoBlockTransactionMkTreeNode::Block {
                block_hash,
                block_number,
                slot_number,
            } => Self::Block {
                block_hash,
                block_number: *block_number,
                slot_number: *slot_number,
            },
            CardanoBlockTransactionMkTreeNode::Transaction {
                transaction_hash,
                block_hash,
                block_number,
                slot_number,
            } => Self::Tx {
                transaction_hash,
                block_hash,
                block_number: *block_number,
                slot_number: *slot_number,
            },
        }
    }
}

/// Canonical contents of a single block range, in Mithril's tree-insertion order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxTreeRangeMessage {
    /// Range start block number (a multiple of [`BlockRange::LENGTH`]).
    pub start: u64,
    /// Range end block number (`start + BlockRange::LENGTH`).
    pub end: u64,
    /// `to_hex` of the sub-tree Merkle root node, exactly as Mithril computes/stores it
    /// (a single-leaf range yields 128 hex chars; a multi-leaf range a 32-byte Blake2s digest).
    pub block_range_root: String,
    /// v1: transaction hashes in tree-insertion order. Absent for v2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordered_txids: Option<Vec<String>>,
    /// v2: interleaved Block + Tx nodes in tree-insertion order. Absent for v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordered_nodes: Option<Vec<TxTreeNodeMessage>>,
}

/// One `(range, block_range_root)` entry of the frontier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxTreeRangeRootMessage {
    /// Range start block number.
    pub start: u64,
    /// Range end block number (`start + BlockRange::LENGTH`).
    pub end: u64,
    /// `to_hex` of the sub-tree Merkle root node, exactly as stored.
    pub block_range_root: String,
}

/// The set of ranges (a page of it) that bag to the certificate-signed root `X` at a tip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxTreeFrontierMessage {
    /// Hash of the certificate certified at-or-below the requested `up_to_block_number`.
    pub certificate_hash: String,
    /// The `CardanoTransactionsMerkleRoot` (`X`) that certificate signs.
    pub cardano_transactions_merkle_root: String,
    /// The certificate's beacon block number (the effective tip the ranges bag to).
    pub beacon: u64,
    /// `BlockRange::LENGTH` (15).
    pub block_range_length: u64,
    /// A page of `(range, block_range_root)` entries ordered by `start`.
    pub ranges: Vec<TxTreeRangeRootMessage>,
    /// `start` to pass back to fetch the next page, or `None` if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_start: Option<u64>,
}

/// Default maximum number of ranges returned by one frontier page.
const FRONTIER_DEFAULT_LIMIT: usize = 5_000;

/// Service exposing the canonical per-range transaction-tree inputs.
pub struct TxTreeService {
    signed_entity_service: Arc<dyn SignedEntityService>,
    chain_data_repository: Arc<AggregatorCardanoChainDataRepository>,
}

/// The certificate a request resolves to (its beacon + signed root).
struct ResolvedAnchor {
    certificate_hash: String,
    cardano_transactions_merkle_root: String,
    beacon: BlockNumber,
}

impl TxTreeService {
    /// Create a new `TxTreeService`.
    pub fn new(
        signed_entity_service: Arc<dyn SignedEntityService>,
        chain_data_repository: Arc<AggregatorCardanoChainDataRepository>,
    ) -> Self {
        Self {
            signed_entity_service,
            chain_data_repository,
        }
    }

    /// Resolve `up_to` to the certificate certified at-or-below it (same resolution as the proof
    /// route). `None` means no certificate at-or-below `up_to` exists (the caller returns 404).
    async fn resolve_anchor(
        &self,
        up_to: BlockNumber,
        version: TxTreeVersion,
    ) -> StdResult<Option<ResolvedAnchor>> {
        let anchor = match version {
            TxTreeVersion::V1 => self
                .signed_entity_service
                .get_cardano_transaction_snapshot_at_or_below_block_number(up_to)
                .await?
                .map(|se| ResolvedAnchor {
                    certificate_hash: se.certificate_id,
                    cardano_transactions_merkle_root: se.artifact.merkle_root,
                    beacon: se.artifact.block_number,
                }),
            TxTreeVersion::V2 => self
                .signed_entity_service
                .get_cardano_blocks_transactions_snapshot_at_or_below_block_number(up_to)
                .await?
                .map(|se| ResolvedAnchor {
                    certificate_hash: se.certificate_id,
                    cardano_transactions_merkle_root: se.artifact.merkle_root,
                    beacon: se.artifact.block_number_signed,
                }),
        };

        Ok(anchor)
    }

    /// Return the canonical contents of the block range starting at `start`, as of the certificate
    /// certified at-or-below `up_to`. `None` if no such certificate, or `start` is beyond its beacon.
    pub async fn range(
        &self,
        start: BlockNumber,
        up_to: BlockNumber,
        version: TxTreeVersion,
    ) -> StdResult<Option<TxTreeRangeMessage>> {
        let Some(anchor) = self.resolve_anchor(up_to, version).await? else {
            return Ok(None);
        };
        if start > anchor.beacon {
            return Ok(None);
        }

        // Trailing range is capped at the beacon, matching the certificate's partial last range.
        let nominal_end = start + BlockRange::LENGTH;
        let fetch_end = nominal_end.min(anchor.beacon + 1);

        let (block_range_root, ordered_txids, ordered_nodes) = match version {
            TxTreeVersion::V1 => {
                let transactions = self
                    .chain_data_repository
                    .get_transactions_in_range(start..fetch_end)
                    .await?;
                if transactions.is_empty() {
                    return Ok(None);
                }
                let root = MKTree::<MKTreeStoreInMemory>::new(&transactions)
                    .and_then(|tree| tree.compute_root())
                    .with_context(|| format!("Failed to compute v1 block range root at {start}"))?
                    .to_hex();
                let txids = transactions.into_iter().map(|tx| tx.transaction_hash).collect();
                (root, Some(txids), None)
            }
            TxTreeVersion::V2 => {
                let nodes = self
                    .chain_data_repository
                    .get_blocks_and_transactions_in_range(start..fetch_end)
                    .await?;
                if nodes.is_empty() {
                    return Ok(None);
                }
                let root = MKTree::<MKTreeStoreInMemory>::new_from_iter(nodes.clone())
                    .and_then(|tree| tree.compute_root())
                    .with_context(|| format!("Failed to compute v2 block range root at {start}"))?
                    .to_hex();
                let messages = nodes.into_iter().map(TxTreeNodeMessage::from).collect();
                (root, None, Some(messages))
            }
        };

        Ok(Some(TxTreeRangeMessage {
            start: *start,
            end: *nominal_end,
            block_range_root,
            ordered_txids,
            ordered_nodes,
        }))
    }

    /// Compute the `to_hex` sub-tree root over the leaves of `[start, end)` for `version`.
    /// `None` if the range holds no leaves.
    async fn computed_root(
        &self,
        start: BlockNumber,
        end: BlockNumber,
        version: TxTreeVersion,
    ) -> StdResult<Option<String>> {
        let root = match version {
            TxTreeVersion::V1 => {
                let transactions = self
                    .chain_data_repository
                    .get_transactions_in_range(start..end)
                    .await?;
                if transactions.is_empty() {
                    return Ok(None);
                }
                MKTree::<MKTreeStoreInMemory>::new(&transactions)
                    .and_then(|tree| tree.compute_root())
                    .with_context(|| format!("Failed to compute v1 block range root at {start}"))?
                    .to_hex()
            }
            TxTreeVersion::V2 => {
                let nodes = self
                    .chain_data_repository
                    .get_blocks_and_transactions_in_range(start..end)
                    .await?;
                if nodes.is_empty() {
                    return Ok(None);
                }
                MKTree::<MKTreeStoreInMemory>::new_from_iter(nodes)
                    .and_then(|tree| tree.compute_root())
                    .with_context(|| format!("Failed to compute v2 block range root at {start}"))?
                    .to_hex()
            }
        };

        Ok(Some(root))
    }

    /// Return one page of the ranges (and their stored roots) that bag to `X` at `up_to`, plus the
    /// resolved certificate + `X`. `None` if no certificate is certified at-or-below `up_to`.
    pub async fn frontier(
        &self,
        up_to: BlockNumber,
        version: TxTreeVersion,
        from_start: Option<BlockNumber>,
        limit: Option<usize>,
    ) -> StdResult<Option<TxTreeFrontierMessage>> {
        let Some(anchor) = self.resolve_anchor(up_to, version).await? else {
            return Ok(None);
        };
        let limit = limit.unwrap_or(FRONTIER_DEFAULT_LIMIT).max(1);
        let from_start = from_start.unwrap_or(BlockNumber(0));

        // Stored (sealed) block-range roots up to the certificate's beacon, ordered by start.
        let roots_iterator = match version {
            TxTreeVersion::V1 => {
                self.chain_data_repository
                    .retrieve_legacy_block_range_roots_up_to(anchor.beacon)
                    .await?
            }
            TxTreeVersion::V2 => {
                self.chain_data_repository
                    .retrieve_block_range_roots_up_to(anchor.beacon)
                    .await?
            }
        };

        let mut ranges: Vec<TxTreeRangeRootMessage> = roots_iterator
            .map(|(range, root)| TxTreeRangeRootMessage {
                start: *range.start,
                end: *range.end,
                block_range_root: root.to_hex(),
            })
            .collect();

        // The certificate's tree includes a partial trailing range whenever the beacon does not fall
        // on a block-range boundary. Replicate `compute_merkle_map_from_block_range_roots` so the
        // returned ranges bag to X (a sealed range already covering the beacon needs no partial).
        let latest_block_range = BlockRange::from_block_number(anchor.beacon);
        let beacon = *anchor.beacon;
        let beacon_in_last_range = ranges
            .iter()
            .map(|r| (r.start, r.end))
            .max()
            .map(|(start, end)| start <= beacon && beacon < end)
            .unwrap_or(false);
        if !latest_block_range.is_fully_covered_at(anchor.beacon) && !beacon_in_last_range {
            let partial_end =
                (latest_block_range.start + BlockRange::LENGTH).min(anchor.beacon + 1);
            if let Some(root) = self
                .computed_root(latest_block_range.start, partial_end, version)
                .await?
            {
                ranges.push(TxTreeRangeRootMessage {
                    start: *latest_block_range.start,
                    end: *(latest_block_range.start + BlockRange::LENGTH),
                    block_range_root: root,
                });
            }
        }

        // Pagination (the partial range, if present, has the highest start and sorts last).
        ranges.sort_by_key(|r| r.start);
        ranges.retain(|r| r.start >= *from_start);
        let next_start = if ranges.len() > limit {
            let next = ranges[limit].start;
            ranges.truncate(limit);
            Some(BlockNumber(next))
        } else {
            None
        };

        Ok(Some(TxTreeFrontierMessage {
            certificate_hash: anchor.certificate_hash,
            cardano_transactions_merkle_root: anchor.cardano_transactions_merkle_root,
            beacon: *anchor.beacon,
            block_range_length: *BlockRange::LENGTH,
            ranges,
            next_start: next_start.map(|n| *n),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_query_parameter() {
        assert_eq!(Some(TxTreeVersion::V1), TxTreeVersion::parse("v1"));
        assert_eq!(Some(TxTreeVersion::V2), TxTreeVersion::parse("v2"));
        assert_eq!(None, TxTreeVersion::parse("v3"));
        assert_eq!(None, TxTreeVersion::parse(""));
    }

    #[test]
    fn v2_node_serializes_with_type_tag_and_raw_values() {
        let block = TxTreeNodeMessage::Block {
            block_hash: "abcd".to_string(),
            block_number: 12,
            slot_number: 34,
        };
        assert_eq!(
            serde_json::json!({"type": "Block", "block_hash": "abcd", "block_number": 12, "slot_number": 34}),
            serde_json::to_value(&block).unwrap()
        );

        let tx = TxTreeNodeMessage::Tx {
            transaction_hash: "ef01".to_string(),
            block_hash: "abcd".to_string(),
            block_number: 12,
            slot_number: 34,
        };
        assert_eq!(
            serde_json::json!({"type": "Tx", "transaction_hash": "ef01", "block_hash": "abcd", "block_number": 12, "slot_number": 34}),
            serde_json::to_value(&tx).unwrap()
        );
    }

    #[test]
    fn range_message_omits_the_other_version_field() {
        let v1 = TxTreeRangeMessage {
            start: 0,
            end: 15,
            block_range_root: "deadbeef".to_string(),
            ordered_txids: Some(vec!["aa".to_string()]),
            ordered_nodes: None,
        };
        let value = serde_json::to_value(&v1).unwrap();
        assert!(value.get("ordered_txids").is_some());
        assert!(value.get("ordered_nodes").is_none());
    }

    #[test]
    fn converts_mk_tree_nodes_to_messages() {
        use mithril_common::entities::{BlockNumber, SlotNumber};

        let block = CardanoBlockTransactionMkTreeNode::Block {
            block_hash: "h".to_string(),
            block_number: BlockNumber(5),
            slot_number: SlotNumber(6),
        };
        assert_eq!(
            TxTreeNodeMessage::Block {
                block_hash: "h".to_string(),
                block_number: 5,
                slot_number: 6
            },
            TxTreeNodeMessage::from(block)
        );
    }
}
