use anyhow::{Context, anyhow};
use async_trait::async_trait;

use mithril_common::certificate_chain::{CertificateRetriever, CertificateRetrieverError};
use mithril_common::entities::Certificate;

use crate::AggregatorHttpClient;
use crate::query::GetCertificateQuery;

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateRetriever for AggregatorHttpClient {
    async fn get_certificate_details(
        &self,
        certificate_hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        let message = self
            .send(GetCertificateQuery::by_hash(certificate_hash))
            .await
            .with_context(|| {
                format!("Failed to retrieve certificate with hash: '{certificate_hash}'")
            })
            .map_err(CertificateRetrieverError)?
            .ok_or(CertificateRetrieverError(anyhow!(
                "Certificate does not exist: '{certificate_hash}'"
            )))?;

        message.try_into().map_err(CertificateRetrieverError)
    }
}
