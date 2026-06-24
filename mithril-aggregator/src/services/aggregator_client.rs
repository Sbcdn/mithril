use async_trait::async_trait;

use mithril_aggregator_client::{
    AggregatorHttpClient,
    query::{
        GetCertificateQuery, GetCertificatesListQuery, GetEpochSettingsQuery,
        GetMithrilStakeDistributionQuery, GetMithrilStakeDistributionsListQuery,
    },
};
use mithril_common::{
    StdResult,
    entities::{Certificate, Epoch, SignedEntityType},
    messages::{MithrilStakeDistributionMessage, SignedEntityTypeMessage, TryFromMessageAdapter},
};

use crate::entities::LeaderAggregatorEpochSettings;
use crate::message_adapters::FromEpochSettingsAdapter;
use crate::services::{LeaderAggregatorClient, RemoteCertificateRetriever};

#[async_trait]
impl LeaderAggregatorClient for AggregatorHttpClient {
    async fn retrieve_epoch_settings(&self) -> StdResult<Option<LeaderAggregatorEpochSettings>> {
        let epoch_settings = self.send(GetEpochSettingsQuery::current()).await?;
        FromEpochSettingsAdapter::try_adapt(epoch_settings).map(Some)
    }

    async fn retrieve_mithril_stake_distribution(
        &self,
        epoch: Epoch,
    ) -> StdResult<Option<MithrilStakeDistributionMessage>> {
        let stake_distributions_list =
            self.send(GetMithrilStakeDistributionsListQuery::latest()).await?;

        match stake_distributions_list.iter().find(|item| item.epoch == epoch) {
            None => Ok(None),
            Some(item) => Ok(self
                .send(GetMithrilStakeDistributionQuery::by_hash(&item.hash))
                .await?),
        }
    }
}

#[async_trait]
impl RemoteCertificateRetriever for AggregatorHttpClient {
    async fn get_latest_certificate_details(&self) -> StdResult<Option<Certificate>> {
        let latest_certificates_list = self.send(GetCertificatesListQuery::latest()).await?;

        match latest_certificates_list.first() {
            None => Ok(None),
            Some(latest_certificate_list_item) => {
                let latest_certificate_message = self
                    .send(GetCertificateQuery::by_hash(
                        &latest_certificate_list_item.hash,
                    ))
                    .await?;
                latest_certificate_message.map(TryInto::try_into).transpose()
            }
        }
    }

    async fn get_latest_cardano_transactions_certificate_details(
        &self,
    ) -> StdResult<Option<Certificate>> {
        let latest_certificates_list = self.send(GetCertificatesListQuery::latest()).await?;

        match latest_certificates_list.iter().find(|item| {
            matches!(
                item.signed_entity_type,
                SignedEntityTypeMessage::Known(SignedEntityType::CardanoTransactions(..))
            )
        }) {
            None => Ok(None),
            Some(certificate_list_item) => {
                let certificate_message = self
                    .send(GetCertificateQuery::by_hash(&certificate_list_item.hash))
                    .await?;
                certificate_message.map(TryInto::try_into).transpose()
            }
        }
    }

    async fn get_genesis_certificate_details(&self) -> StdResult<Option<Certificate>> {
        match self.send(GetCertificateQuery::latest_genesis()).await? {
            Some(message) => Ok(Some(message.try_into()?)),
            None => Ok(None),
        }
    }
}
