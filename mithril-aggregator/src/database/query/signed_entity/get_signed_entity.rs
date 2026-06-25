use sqlite::Value;

use mithril_common::StdResult;
use mithril_common::entities::{BlockNumber, Epoch, SignedEntityTypeDiscriminants};
use mithril_persistence::sqlite::{Query, SourceAlias, SqLiteEntity, WhereCondition};

use crate::database::record::SignedEntityRecord;

/// Default result ordering, by insertion order (most recent first).
const ORDER_BY_ROWID_DESC: &str = "ROWID desc";
/// Result ordering for the "at or below block number" queries: highest certified block
/// first, independent of physical insertion order (`ROWID` only breaks ties).
const ORDER_BY_BLOCK_NUMBER_DESC: &str =
    "cast(json_extract(beacon, '$.block_number') as integer) desc, ROWID desc";

/// Simple queries to retrieve [SignedEntityRecord] from the sqlite database.
pub struct GetSignedEntityRecordQuery {
    condition: WhereCondition,
    order_by: &'static str,
}

impl GetSignedEntityRecordQuery {
    fn new(condition: WhereCondition) -> Self {
        Self {
            condition,
            order_by: ORDER_BY_ROWID_DESC,
        }
    }

    fn ordered_by(mut self, order_by: &'static str) -> Self {
        self.order_by = order_by;
        self
    }

    #[cfg(test)]
    pub fn all() -> Self {
        Self::new(WhereCondition::default())
    }

    pub fn by_signed_entity_id_and_signed_entity_type(
        signed_entity_id: &str,
        signed_entity_type: &SignedEntityTypeDiscriminants,
    ) -> Self {
        let signed_entity_type_id = signed_entity_type.index() as i64;
        Self::new(WhereCondition::new(
            "signed_entity_id = ?* and signed_entity_type_id = ?*",
            vec![
                Value::String(signed_entity_id.to_owned()),
                Value::Integer(signed_entity_type_id),
            ],
        ))
    }

    pub fn by_certificate_id(certificate_id: &str) -> Self {
        Self::new(WhereCondition::new(
            "certificate_id = ?*",
            vec![Value::String(certificate_id.to_owned())],
        ))
    }

    pub fn by_certificates_ids(certificates_ids: &[&str]) -> Self {
        let ids_values = certificates_ids
            .iter()
            .map(|id| Value::String(id.to_string()))
            .collect();

        Self::new(WhereCondition::where_in("certificate_id", ids_values))
    }

    pub fn by_signed_entity_type(
        signed_entity_type: &SignedEntityTypeDiscriminants,
    ) -> StdResult<Self> {
        let signed_entity_type_id: i64 = signed_entity_type.index() as i64;

        Ok(Self::new(WhereCondition::new(
            "signed_entity_type_id = ?*",
            vec![Value::Integer(signed_entity_type_id)],
        )))
    }

    pub fn by_signed_entity_type_and_epoch(
        signed_entity_type: &SignedEntityTypeDiscriminants,
        epoch: Epoch,
    ) -> Self {
        let signed_entity_type_id = signed_entity_type.index() as i64;
        let epoch = *epoch as i64;

        Self::new(WhereCondition::new(
            "signed_entity_type_id = ?* and epoch = ?*",
            vec![Value::Integer(signed_entity_type_id), Value::Integer(epoch)],
        ))
    }

    /// Retrieve the most recent [CardanoTransactions][SignedEntityTypeDiscriminants::CardanoTransactions]
    /// signed entity certified at or below the given block number.
    ///
    /// The CardanoTransactions beacon is stored as a JSON object
    /// (`{"epoch":E,"block_number":B}`); the query filters and orders on the extracted
    /// `block_number`, so `fetch_first` returns the highest certified block at or below
    /// the bound regardless of the rows' physical insertion order.
    pub fn cardano_transaction_at_or_below_block_number(block_number: BlockNumber) -> Self {
        let signed_entity_type_id =
            SignedEntityTypeDiscriminants::CardanoTransactions.index() as i64;
        let block_number = *block_number as i64;

        Self::new(WhereCondition::new(
            "signed_entity_type_id = ?* and cast(json_extract(beacon, '$.block_number') as integer) <= ?*",
            vec![Value::Integer(signed_entity_type_id), Value::Integer(block_number)],
        ))
        .ordered_by(ORDER_BY_BLOCK_NUMBER_DESC)
    }

    /// Retrieve the most recent
    /// [CardanoBlocksTransactions][SignedEntityTypeDiscriminants::CardanoBlocksTransactions]
    /// (v2) signed entity certified at or below the given block number.
    ///
    /// The CardanoBlocksTransactions beacon is stored as a JSON object
    /// (`{"epoch":E,"block_number":B,"block_number_offset":O}`); like the v1 variant the
    /// query filters and orders on the extracted `block_number`, so `fetch_first` returns
    /// the highest certified block at or below the bound regardless of insertion order.
    pub fn cardano_blocks_transactions_at_or_below_block_number(block_number: BlockNumber) -> Self {
        let signed_entity_type_id =
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions.index() as i64;
        let block_number = *block_number as i64;

        Self::new(WhereCondition::new(
            "signed_entity_type_id = ?* and cast(json_extract(beacon, '$.block_number') as integer) <= ?*",
            vec![Value::Integer(signed_entity_type_id), Value::Integer(block_number)],
        ))
        .ordered_by(ORDER_BY_BLOCK_NUMBER_DESC)
    }
}

impl Query for GetSignedEntityRecordQuery {
    type Entity = SignedEntityRecord;

    fn filters(&self) -> WhereCondition {
        self.condition.clone()
    }

    fn get_definition(&self, condition: &str) -> String {
        let aliases = SourceAlias::new(&[("{:signed_entity:}", "se")]);
        let projection = Self::Entity::get_projection().expand(aliases);
        let order_by = self.order_by;
        format!(
            "select {projection} from signed_entity as se where {condition} order by {order_by}"
        )
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::{BlockNumber, CardanoDbBeacon, SignedEntityType};
    use mithril_persistence::sqlite::ConnectionExtensions;
    use sqlite::ConnectionThreadSafe;

    use crate::database::test_helper::{insert_signed_entities, main_db_connection};

    use super::*;

    fn create_database(records: &[SignedEntityRecord]) -> ConnectionThreadSafe {
        let connection = main_db_connection().unwrap();
        insert_signed_entities(&connection, records.to_vec()).unwrap();

        connection
    }

    #[test]
    fn by_signed_entity_and_epoch_returns_records_filtered_by_epoch() {
        let records = vec![
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::CardanoStakeDistribution(Epoch(3)),
            ),
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::CardanoStakeDistribution(Epoch(4)),
            ),
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::CardanoStakeDistribution(Epoch(5)),
            ),
        ];

        let connection = create_database(&records);

        let records_retrieved: Vec<SignedEntityRecord> = connection
            .fetch_collect(GetSignedEntityRecordQuery::by_signed_entity_type_and_epoch(
                &SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                Epoch(4),
            ))
            .unwrap();

        assert_eq!(vec![records[1].clone()], records_retrieved);
    }

    #[test]
    fn by_signed_entity_and_epoch_returns_records_filtered_by_discriminant() {
        let records = vec![
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::CardanoStakeDistribution(Epoch(3)),
            ),
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::MithrilStakeDistribution(Epoch(3)),
            ),
            SignedEntityRecord::fake_with_signed_entity(SignedEntityType::CardanoDatabase(
                CardanoDbBeacon::new(3, 98),
            )),
        ];

        let connection = create_database(&records);

        let fetched_msd_records: Vec<SignedEntityRecord> = connection
            .fetch_collect(GetSignedEntityRecordQuery::by_signed_entity_type_and_epoch(
                &SignedEntityTypeDiscriminants::MithrilStakeDistribution,
                Epoch(3),
            ))
            .unwrap();
        assert_eq!(vec![records[1].clone()], fetched_msd_records);

        let fetched_cdb_records: Vec<SignedEntityRecord> = connection
            .fetch_collect(GetSignedEntityRecordQuery::by_signed_entity_type_and_epoch(
                &SignedEntityTypeDiscriminants::CardanoDatabase,
                Epoch(3),
            ))
            .unwrap();
        assert_eq!(vec![records[2].clone()], fetched_cdb_records);
    }

    #[test]
    fn test_get_record_by_id_and_signed_entity_type() {
        let signed_entity_records = vec![
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::CardanoStakeDistribution(Epoch(3)),
            ),
            SignedEntityRecord::fake_with_signed_entity(SignedEntityType::CardanoTransactions(
                Epoch(4),
                BlockNumber(5),
            )),
        ];

        let connection = main_db_connection().unwrap();
        insert_signed_entities(&connection, signed_entity_records.clone()).unwrap();

        let first_signed_entity_type = signed_entity_records[0].clone();
        let fetched_record = connection
            .fetch_first(
                GetSignedEntityRecordQuery::by_signed_entity_id_and_signed_entity_type(
                    &first_signed_entity_type.signed_entity_id,
                    &SignedEntityTypeDiscriminants::CardanoStakeDistribution,
                ),
            )
            .unwrap();
        assert_eq!(Some(first_signed_entity_type), fetched_record);
    }

    #[test]
    fn test_get_record_by_id_and_signed_entity_type_must_return_none_if_signed_entity_type_does_not_match()
     {
        let signed_entity_records = vec![
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::CardanoStakeDistribution(Epoch(3)),
            ),
            SignedEntityRecord::fake_with_signed_entity(SignedEntityType::CardanoTransactions(
                Epoch(4),
                BlockNumber(5),
            )),
        ];

        let connection = main_db_connection().unwrap();
        insert_signed_entities(&connection, signed_entity_records.clone()).unwrap();

        let first_signed_entity_type = signed_entity_records[0].clone();
        let fetched_record = connection
            .fetch_first(
                GetSignedEntityRecordQuery::by_signed_entity_id_and_signed_entity_type(
                    &first_signed_entity_type.signed_entity_id,
                    &SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
                ),
            )
            .unwrap();
        assert_eq!(None, fetched_record);
    }

    #[test]
    fn test_get_record_by_signed_entity_type() {
        let signed_entity_records = vec![
            SignedEntityRecord::fake_with_signed_entity(
                SignedEntityType::MithrilStakeDistribution(Epoch(2)),
            ),
            SignedEntityRecord::fake_with_signed_entity(SignedEntityType::CardanoTransactions(
                Epoch(4),
                BlockNumber(5),
            )),
            SignedEntityRecord::fake_with_signed_entity(SignedEntityType::CardanoTransactions(
                Epoch(5),
                BlockNumber(9),
            )),
        ];

        let connection = main_db_connection().unwrap();
        insert_signed_entities(&connection, signed_entity_records.clone()).unwrap();

        let fetched_tx_records: Vec<SignedEntityRecord> = connection
            .fetch_collect(
                GetSignedEntityRecordQuery::by_signed_entity_type(
                    &SignedEntityTypeDiscriminants::CardanoTransactions,
                )
                .unwrap(),
            )
            .unwrap();
        let expected_tx_records: Vec<SignedEntityRecord> =
            vec![signed_entity_records[2].clone(), signed_entity_records[1].clone()];
        assert_eq!(expected_tx_records, fetched_tx_records);
    }

    #[test]
    fn test_get_all_records() {
        let signed_entity_records = SignedEntityRecord::fake_records(5);

        let connection = main_db_connection().unwrap();
        insert_signed_entities(&connection, signed_entity_records.clone()).unwrap();

        let fetched_records: Vec<SignedEntityRecord> =
            connection.fetch_collect(GetSignedEntityRecordQuery::all()).unwrap();
        let expected_signed_entity_records: Vec<_> =
            signed_entity_records.into_iter().rev().collect();
        assert_eq!(expected_signed_entity_records, fetched_records);
    }

    fn cardano_transaction_record(block_number: u64) -> SignedEntityRecord {
        use mithril_common::entities::CardanoTransactionsSnapshot;

        let artifact = CardanoTransactionsSnapshot::new(
            format!("merkle-root-{block_number}"),
            BlockNumber(block_number),
        );
        SignedEntityRecord {
            signed_entity_id: format!("ct-{block_number}"),
            signed_entity_type: SignedEntityType::CardanoTransactions(
                Epoch(1),
                BlockNumber(block_number),
            ),
            certificate_id: format!("certificate-ct-{block_number}"),
            artifact: serde_json::to_string(&artifact).unwrap(),
            created_at: chrono::DateTime::default(),
        }
    }

    #[test]
    fn cardano_transaction_at_or_below_block_number_returns_highest_certified_at_or_below() {
        // Inserted in increasing block order (as the chain advances).
        let records = vec![
            cardano_transaction_record(100),
            cardano_transaction_record(200),
            cardano_transaction_record(300),
        ];
        let connection = create_database(&records);

        let retrieved: Vec<SignedEntityRecord> = connection
            .fetch_collect(
                GetSignedEntityRecordQuery::cardano_transaction_at_or_below_block_number(
                    BlockNumber(250),
                ),
            )
            .unwrap();

        // 100 and 200 qualify (<= 250); 300 is excluded. Highest block first, so
        // `fetch_first` returns 200 at the route.
        assert_eq!(records[1], retrieved[0]);
        assert!(!retrieved.contains(&records[2]));
    }

    #[test]
    fn cardano_transaction_at_or_below_block_number_ignores_other_signed_entity_types() {
        let cardano_stake_distribution = SignedEntityRecord::fake_with_signed_entity(
            SignedEntityType::CardanoStakeDistribution(Epoch(4)),
        );
        let connection =
            create_database(&[cardano_stake_distribution, cardano_transaction_record(150)]);

        let retrieved: Vec<SignedEntityRecord> = connection
            .fetch_collect(
                GetSignedEntityRecordQuery::cardano_transaction_at_or_below_block_number(
                    BlockNumber(1_000),
                ),
            )
            .unwrap();

        assert_eq!(vec![cardano_transaction_record(150)], retrieved);
    }

    #[test]
    fn cardano_transaction_at_or_below_block_number_orders_by_block_not_insertion_order() {
        // Inserted with the higher block first, so the highest-at-or-below row does not
        // have the highest ROWID (as can happen after a certificate-hash migration that
        // deletes and re-inserts rows). The result must still be the highest block.
        let connection =
            create_database(&[cardano_transaction_record(200), cardano_transaction_record(100)]);

        let retrieved: Vec<SignedEntityRecord> = connection
            .fetch_collect(
                GetSignedEntityRecordQuery::cardano_transaction_at_or_below_block_number(
                    BlockNumber(250),
                ),
            )
            .unwrap();

        assert_eq!(cardano_transaction_record(200), retrieved[0]);
    }

    fn cardano_blocks_transactions_record(block_number: u64) -> SignedEntityRecord {
        use mithril_common::entities::{BlockNumberOffset, CardanoBlocksTransactionsSnapshot};

        let artifact = CardanoBlocksTransactionsSnapshot::new(
            format!("merkle-root-{block_number}"),
            BlockNumber(block_number),
            BlockNumberOffset(15),
        );
        SignedEntityRecord {
            signed_entity_id: format!("bt-{block_number}"),
            signed_entity_type: SignedEntityType::CardanoBlocksTransactions(
                Epoch(1),
                BlockNumber(block_number),
                BlockNumberOffset(15),
            ),
            certificate_id: format!("certificate-bt-{block_number}"),
            artifact: serde_json::to_string(&artifact).unwrap(),
            created_at: chrono::DateTime::default(),
        }
    }

    #[test]
    fn cardano_blocks_transactions_at_or_below_block_number_returns_highest_certified_at_or_below()
    {
        // Inserted in increasing block order (as the chain advances).
        let records = vec![
            cardano_blocks_transactions_record(100),
            cardano_blocks_transactions_record(200),
            cardano_blocks_transactions_record(300),
        ];
        let connection = create_database(&records);

        let retrieved: Vec<SignedEntityRecord> = connection
            .fetch_collect(
                GetSignedEntityRecordQuery::cardano_blocks_transactions_at_or_below_block_number(
                    BlockNumber(250),
                ),
            )
            .unwrap();

        // 100 and 200 qualify (<= 250); 300 is excluded.
        assert_eq!(records[1], retrieved[0]);
        assert!(!retrieved.contains(&records[2]));
    }

    #[test]
    fn cardano_blocks_transactions_at_or_below_block_number_ignores_other_signed_entity_types() {
        // A v1 CardanoTransactions record at the same block must NOT be returned by the
        // v2 query (different discriminant).
        let connection = create_database(&[
            cardano_transaction_record(150),
            cardano_blocks_transactions_record(150),
        ]);

        let retrieved: Vec<SignedEntityRecord> = connection
            .fetch_collect(
                GetSignedEntityRecordQuery::cardano_blocks_transactions_at_or_below_block_number(
                    BlockNumber(1_000),
                ),
            )
            .unwrap();

        assert_eq!(vec![cardano_blocks_transactions_record(150)], retrieved);
    }
}
