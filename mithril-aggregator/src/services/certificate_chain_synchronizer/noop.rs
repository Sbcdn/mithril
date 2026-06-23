use mithril_common::StdResult;
use mithril_common::entities::Certificate;

use crate::services::CertificateChainSynchronizer;

/// A noop [CertificateChainSynchronizer] for leader aggregators
pub struct MithrilCertificateChainSynchronizerNoop;

#[async_trait::async_trait]
impl CertificateChainSynchronizer for MithrilCertificateChainSynchronizerNoop {
    async fn synchronize_certificate_chain(&self, _force: bool) -> StdResult<()> {
        Ok(())
    }

    async fn synchronize_cardano_transactions_certificate(&self) -> StdResult<Option<Certificate>> {
        Ok(None)
    }
}
