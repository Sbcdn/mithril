use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::{
    StdResult,
    crypto_helper::{KesEvolutions, ProtocolKeyRegistration, SignerRegistrationParameters},
    entities::{Signer, SignerWithStake, StakeDistribution},
};

use super::SignerRegistrationVerifier;

/// Implementation of a [SignerRegistrationVerifier]
pub struct MithrilSignerRegistrationVerifier {
    /// Chain observer service.
    chain_observer: Arc<dyn ChainObserver>,
}

impl MithrilSignerRegistrationVerifier {
    /// Creates a new [MithrilSignerRegistrationVerifier].
    pub fn new(chain_observer: Arc<dyn ChainObserver>) -> Self {
        Self { chain_observer }
    }

    /// KES evolution count derived from the *current* KES period. Only correct at the
    /// moment of original registration (the current period is then the signing period).
    async fn current_kes_evolutions(&self, signer: &Signer) -> StdResult<Option<KesEvolutions>> {
        Ok(match &signer.operational_certificate {
            Some(operational_certificate) => Some(
                self.chain_observer
                    .get_current_kes_period()
                    .await?
                    .unwrap_or_default()
                    - operational_certificate.get_start_kes_period(),
            ),
            None => None,
        })
    }

    /// Register the signer against the stake distribution using the provided KES evolution
    /// count (the KES signature is always cryptographically verified against it).
    fn register_signer(
        &self,
        signer: &Signer,
        stake_distribution: &StakeDistribution,
        kes_evolutions: Option<KesEvolutions>,
    ) -> StdResult<SignerWithStake> {
        let mut key_registration = ProtocolKeyRegistration::init(
            &stake_distribution
                .iter()
                .map(|(k, v)| (k.to_owned(), *v))
                .collect::<Vec<_>>(),
        );
        let party_id_register = match signer.party_id.as_str() {
            "" => None,
            party_id => Some(party_id.to_string()),
        };
        let party_id_registered = key_registration
            .register(SignerRegistrationParameters {
                party_id: party_id_register.clone(),
                operational_certificate: signer.operational_certificate.clone(),
                verification_key_signature_for_concatenation: signer
                    .verification_key_signature_for_concatenation,
                kes_evolutions,
                verification_key_for_concatenation: signer.verification_key_for_concatenation,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: signer.verification_key_for_snark,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: signer.verification_key_signature_for_snark,
            })
            .with_context(|| {
                format!(
                    "KeyRegwrapper can not register signer with party_id: '{party_id_register:?}', kes_evolutions: '{kes_evolutions:?}'"
                )
            })?;
        let party_id_registered_stake = *stake_distribution
            .get(&party_id_registered)
            .with_context(|| format!("Stake not found for party_id: '{party_id_registered}"))?;

        Ok(SignerWithStake {
            party_id: party_id_registered,
            ..SignerWithStake::from_signer(signer.to_owned(), party_id_registered_stake)
        })
    }
}

#[async_trait]
impl SignerRegistrationVerifier for MithrilSignerRegistrationVerifier {
    async fn verify(
        &self,
        signer: &Signer,
        stake_distribution: &StakeDistribution,
    ) -> StdResult<SignerWithStake> {
        let kes_evolutions = self.current_kes_evolutions(signer).await?;
        self.register_signer(signer, stake_distribution, kes_evolutions)
    }

    async fn verify_synchronized(
        &self,
        signer: &Signer,
        stake_distribution: &StakeDistribution,
    ) -> StdResult<SignerWithStake> {
        // A synchronized registration already carries the KES evolution count at the time
        // of signature (computed by the producing aggregator at original registration).
        // Use it directly; recomputing from the current KES period would over-count as the
        // chain advances past the registration period, rejecting every signer. Fall back
        // to the current-period recompute only when no count was synchronized.
        let kes_evolutions = match (&signer.operational_certificate, signer.kes_evolutions) {
            (Some(_), Some(synchronized)) => Some(synchronized),
            _ => self.current_kes_evolutions(signer).await?,
        };
        self.register_signer(signer, stake_distribution, kes_evolutions)
    }
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::{
        entities::TimePoint,
        test::{builder::MithrilFixtureBuilder, double::Dummy},
    };

    use super::*;

    #[tokio::test]
    async fn verify_succeeds_with_valid_signer_registration() {
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();
        let signer_registration_verifier = MithrilSignerRegistrationVerifier::new(Arc::new(
            FakeChainObserver::new(Some(TimePoint::dummy())),
        ));

        signer_registration_verifier
            .verify(&signer_to_register, &fixture.stake_distribution())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_fails_with_invalid_signer_registration() {
        let fixture = MithrilFixtureBuilder::default().with_signers(2).build();
        let signer_to_register: Signer = Signer {
            verification_key_signature_for_concatenation: fixture.signers()[1]
                .verification_key_signature_for_concatenation,
            ..fixture.signers()[0].to_owned()
        };
        let signer_registration_verifier = MithrilSignerRegistrationVerifier::new(Arc::new(
            FakeChainObserver::new(Some(TimePoint::dummy())),
        ));

        signer_registration_verifier
            .verify(&signer_to_register, &fixture.stake_distribution())
            .await
            .expect_err("Verification should fail");
    }

    #[tokio::test]
    async fn verify_synchronized_succeeds_with_valid_signer_registration() {
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();
        let signer_registration_verifier = MithrilSignerRegistrationVerifier::new(Arc::new(
            FakeChainObserver::new(Some(TimePoint::dummy())),
        ));

        signer_registration_verifier
            .verify_synchronized(&signer_to_register, &fixture.stake_distribution())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_synchronized_uses_the_synchronized_kes_evolutions_unlike_verify() {
        // The current KES period is 0 (FakeChainObserver), and the fixture signer's KES
        // signature is valid for evolution count 0. We attach a DELIBERATELY WRONG
        // synchronized evolution count (5) to the same signer.
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let signer_with_wrong_synchronized_evolutions = Signer {
            kes_evolutions: Some(KesEvolutions(5)),
            ..fixture.signers()[0].to_owned()
        };
        let verifier = MithrilSignerRegistrationVerifier::new(Arc::new(FakeChainObserver::new(
            Some(TimePoint::dummy()),
        )));

        // Leader path: recomputes from the current period (0), ignoring the synchronized
        // field, so it still accepts the signer — leader behaviour is unchanged.
        verifier
            .verify(
                &signer_with_wrong_synchronized_evolutions,
                &fixture.stake_distribution(),
            )
            .await
            .expect("verify must recompute and ignore the synchronized kes_evolutions");

        // Follower path: uses the synchronized count (5), so the wrong value is rejected —
        // proving it uses the synchronized value rather than recomputing.
        verifier
            .verify_synchronized(
                &signer_with_wrong_synchronized_evolutions,
                &fixture.stake_distribution(),
            )
            .await
            .expect_err("verify_synchronized must use the synchronized kes_evolutions");
    }
}
