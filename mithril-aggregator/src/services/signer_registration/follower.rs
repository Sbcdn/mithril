use std::sync::Arc;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use slog::{Logger, info, warn};

use mithril_common::{
    StdResult,
    certificate_chain::{CertificateRetriever, CertificateVerifier},
    crypto_helper::{GenesisVerifier, ProtocolKey},
    entities::{
        Epoch, ProtocolMessagePartKey, SignedEntityType, Signer, SignerWithStake, StakeDistribution,
    },
    logging::LoggerExtensions,
    messages::SignerWithStakeMessagePart,
    protocol::SignerBuilder,
};
use mithril_persistence::store::StakeStorer;

use crate::{
    SignerRegistrationVerifier, VerificationKeyStorer, dependency_injection::EpochServiceWrapper,
};

use super::{
    LeaderAggregatorClient, SignerRecorder, SignerRegisterer, SignerRegistrationError,
    SignerRegistrationRound, SignerRegistrationRoundOpener, SignerSynchronizer,
};

/// A [MithrilSignerRegistrationFollower] supports signer registrations in a follower aggregator
pub struct MithrilSignerRegistrationFollower {
    /// Epoch service
    pub epoch_service: EpochServiceWrapper,

    /// Verification key store
    verification_key_store: Arc<dyn VerificationKeyStorer>,

    /// Signer recorder
    signer_recorder: Arc<dyn SignerRecorder>,

    /// Signer registration verifier
    signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,

    /// Leader aggregator client
    leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,

    /// Stake store
    stake_store: Arc<dyn StakeStorer>,

    /// Certificate retriever used to fetch the bootstrap stake-distribution certificate (and, via
    /// the verifier, its parents) by hash from the leader
    certificate_retriever: Arc<dyn CertificateRetriever>,

    /// Certificate verifier (used to anchor a bootstrap stake distribution to genesis)
    certificate_verifier: Arc<dyn CertificateVerifier>,

    /// Genesis verifier (the trust root the bootstrap certificate chain is verified against)
    genesis_verifier: Arc<GenesisVerifier>,

    /// Logger
    logger: Logger,
}

impl MithrilSignerRegistrationFollower {
    /// MithrilSignerRegistererFollower factory
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_service: EpochServiceWrapper,
        verification_key_store: Arc<dyn VerificationKeyStorer>,
        signer_recorder: Arc<dyn SignerRecorder>,
        signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
        leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,
        stake_store: Arc<dyn StakeStorer>,
        certificate_retriever: Arc<dyn CertificateRetriever>,
        certificate_verifier: Arc<dyn CertificateVerifier>,
        genesis_verifier: Arc<GenesisVerifier>,
        logger: Logger,
    ) -> Self {
        Self {
            epoch_service,
            verification_key_store,
            signer_recorder,
            signer_registration_verifier,
            leader_aggregator_client,
            stake_store,
            certificate_retriever,
            certificate_verifier,
            genesis_verifier,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn synchronize_signers(
        &self,
        epoch: Epoch,
        signers: &[Signer],
        stake_distribution: &StakeDistribution,
    ) -> Result<(), SignerRegistrationError> {
        for signer in signers {
            let signer_with_stake = self
                .signer_registration_verifier
                .verify_synchronized(signer, stake_distribution)
                .await
                .map_err(|err| {
                    SignerRegistrationError::InvalidSignerRegistration(
                        signer.party_id.clone(),
                        epoch,
                        err,
                    )
                })?;

            self.signer_recorder
                .record_signer_registration(signer_with_stake.party_id.clone())
                .await
                .map_err(|err| {
                    SignerRegistrationError::FailedSignerRecorder(
                        signer_with_stake.party_id.clone(),
                        epoch,
                        err,
                    )
                })?;

            self
                .verification_key_store
                .save_verification_key(epoch, signer_with_stake.clone())
                .await
                .with_context(|| {
                    format!(
                        "VerificationKeyStorer can not save verification keys for party_id: '{}' for epoch: '{}'",
                        signer_with_stake.party_id,
                        epoch
                    )
                })
                .map_err(SignerRegistrationError::Store)?;
        }

        self.epoch_service
            .write()
            .await
            .update_next_signers_with_stake()
            .await
            .map_err(SignerRegistrationError::EpochService)?;

        Ok(())
    }

    /// Bootstrap the signers and stake of `signer_epoch` from the leader's signed
    /// [MithrilStakeDistribution][mithril_common::entities::MithrilStakeDistribution].
    ///
    /// This is the *trustless* fresh-follower seed: rather than copying an unverified
    /// `/epoch-settings` response, it fetches the stake-distribution artifact for `signer_epoch`
    /// and its certificate from the leader, and accepts the signers only after verifying — the
    /// Mithril way — that they are the genuine set the protocol bound at that epoch:
    ///
    /// 1. the certificate verifies against the genesis-anchored chain
    ///    ([`verify_certificate_chain`][CertificateVerifier::verify_certificate_chain], walking
    ///    each parent up to the genesis certificate via the leader-backed retriever), and
    /// 2. the aggregate verification key recomputed from the artifact's `signers_with_stake`
    ///    equals the `NextAggregateVerificationKey` that certificate signed.
    ///
    /// Only then are the signers + stake written to the stores at `signer_epoch` — the key where
    /// `precompute_epoch_data` reads them. The artifact for epoch `E` carries the signers stored
    /// at key `E`, so the caller passes the store epoch it needs to seed.
    ///
    /// Errors are returned to the caller, which treats them as non-fatal (it logs and falls back
    /// to the slower next-epoch convergence), so this never propagates a `SignerRegistrationError`.
    async fn bootstrap_signer_epoch_from_stake_distribution(
        &self,
        signer_epoch: Epoch,
    ) -> StdResult<()> {
        info!(
            self.logger,
            "Bootstrapping a cold follower's signers from the leader's signed stake distribution";
            "signer_epoch" => ?signer_epoch,
        );

        let stake_distribution = self
            .leader_aggregator_client
            .retrieve_mithril_stake_distribution(signer_epoch)
            .await
            .with_context(|| {
                format!("Failed fetching the stake distribution for epoch {signer_epoch}")
            })?
            .with_context(|| {
                format!("Leader has no stake distribution for epoch {signer_epoch}")
            })?;

        let certificate = self
            .certificate_retriever
            .get_certificate_details(&stake_distribution.certificate_hash)
            .await
            .with_context(|| {
                format!(
                    "Failed fetching certificate '{}'",
                    stake_distribution.certificate_hash
                )
            })?;

        // Trust step 1: the certificate must verify against the genesis-anchored chain. The
        // verifier's retriever is the leader aggregator client, so the walk fetches each parent
        // certificate from the leader up to the genesis certificate (checked against the genesis
        // verification key) — a cold follower has no local chain to anchor against yet.
        self.certificate_verifier
            .verify_certificate_chain(
                certificate.clone(),
                &self.genesis_verifier.to_ed25519_verification_key(),
            )
            .await
            .with_context(|| {
                format!(
                    "Certificate '{}' did not verify against the genesis chain",
                    certificate.hash
                )
            })?;

        // Trust step 1b: bind the verified certificate to `signer_epoch`. The signed entity type is
        // part of the certificate hash, so a leader cannot pass off a (validly signed) certificate
        // for another epoch — or for a different signed entity entirely — as this epoch's stake
        // distribution and thereby seed the wrong signer set.
        let expected_signed_entity_type = SignedEntityType::MithrilStakeDistribution(signer_epoch);
        if certificate.signed_entity_type() != expected_signed_entity_type {
            return Err(anyhow!(
                "Certificate '{}' certifies {:?}, expected {expected_signed_entity_type:?}",
                certificate.hash,
                certificate.signed_entity_type(),
            ));
        }

        let signers_with_stake =
            SignerWithStakeMessagePart::try_into_signers(stake_distribution.signers_with_stake)
                .with_context(|| "Failed parsing the stake distribution signers")?;

        // Trust step 2: the aggregate verification key recomputed from those signers must equal
        // the one the certificate signed (its `NextAggregateVerificationKey`).
        let recomputed_avk = ProtocolKey::new(
            SignerBuilder::new(&signers_with_stake, &stake_distribution.protocol_parameters)
                .with_context(|| "Failed building the signer aggregate")?
                .compute_aggregate_verification_key()
                .to_concatenation_aggregate_verification_key()
                .to_owned(),
        )
        .to_json_hex()
        .with_context(|| "Failed encoding the recomputed aggregate verification key")?;
        let signed_avk = certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::NextAggregateVerificationKey)
            .with_context(|| {
                format!(
                    "Certificate '{}' carries no next aggregate verification key",
                    certificate.hash
                )
            })?;
        if &recomputed_avk != signed_avk {
            return Err(anyhow!(
                "Recomputed aggregate verification key does not match the one signed in certificate '{}'",
                certificate.hash
            ));
        }

        // Verified: seed the stores at `signer_epoch`, where `precompute_epoch_data` reads them.
        let stakes = signers_with_stake
            .iter()
            .map(|signer| (signer.party_id.clone(), signer.stake))
            .collect::<StakeDistribution>();
        self.stake_store
            .save_stakes(signer_epoch, stakes)
            .await
            .with_context(|| {
                format!("Failed saving the bootstrap stakes for epoch {signer_epoch}")
            })?;

        for signer_with_stake in &signers_with_stake {
            self.signer_recorder
                .record_signer_registration(signer_with_stake.party_id.clone())
                .await
                .with_context(|| {
                    format!("Failed recording signer '{}'", signer_with_stake.party_id)
                })?;
            self.verification_key_store
                .save_verification_key(signer_epoch, signer_with_stake.clone())
                .await
                .with_context(|| {
                    format!(
                        "Failed saving the verification key of signer '{}' at epoch {signer_epoch}",
                        signer_with_stake.party_id
                    )
                })?;
        }

        Ok(())
    }
}

#[async_trait]
impl SignerSynchronizer for MithrilSignerRegistrationFollower {
    async fn can_synchronize_signers(&self, epoch: Epoch) -> Result<bool, SignerRegistrationError> {
        Ok(self
            .leader_aggregator_client
            .retrieve_epoch_settings()
            .await
            .with_context(|| "can_synchronize_signers failed")
            .map_err(SignerRegistrationError::FailedFetchingLeaderAggregatorEpochSettings)?
            .is_some_and(|leader_epoch_settings| epoch == leader_epoch_settings.epoch))
    }

    async fn synchronize_all_signers(&self) -> Result<(), SignerRegistrationError> {
        let leader_epoch_settings = self
            .leader_aggregator_client
            .retrieve_epoch_settings()
            .await
            .with_context(|| "synchronize_all_signers failed")
            .map_err(SignerRegistrationError::FailedFetchingLeaderAggregatorEpochSettings)?
            .with_context(|| "Leader aggregator did not return any epoch settings")
            .map_err(SignerRegistrationError::FailedFetchingLeaderAggregatorEpochSettings)?;
        let registration_epoch =
            leader_epoch_settings.epoch.offset_to_leader_synchronization_epoch();
        let signer_retrieval_epoch = registration_epoch
            .offset_to_signer_retrieval_epoch()
            .with_context(|| "synchronize_all_signers failed")
            .map_err(SignerRegistrationError::Store)?;

        // Trustless cold-start bootstrap — MUST run before the per-cycle registration below.
        //
        // `precompute_epoch_data` reads the signers of the signer-retrieval epoch (current − 1).
        // A long-running follower filled it in a previous cycle; a cold-started one has not. The
        // per-cycle `synchronize_signers` call (further down) ends by triggering
        // `precompute_epoch_data`, which fails on that still-empty epoch and aborts the whole
        // function — so the seed has to be committed *first*, here, or it would never run.
        //
        // Seed it from the leader's *signed* `MithrilStakeDistribution` (verified to genesis +
        // AVK recompute), never the unverified epoch-settings. This is best-effort: on failure we
        // log and fall through to the per-cycle path, which seeds the registration epoch and so
        // still converges one epoch transition later (the upstream behaviour). So the follower is
        // never worse off than without the bootstrap, only faster when it succeeds.
        let retrieval_epoch_is_empty = self
            .verification_key_store
            .get_signers(signer_retrieval_epoch)
            .await
            .with_context(|| "synchronize_all_signers failed")
            .map_err(SignerRegistrationError::Store)?
            .is_none_or(|signers| signers.is_empty());
        if retrieval_epoch_is_empty
            && let Err(error) = self
                .bootstrap_signer_epoch_from_stake_distribution(signer_retrieval_epoch)
                .await
        {
            warn!(
                self.logger,
                "Follower failed the trustless cold-start bootstrap of the signer-retrieval epoch; \
                 falling back to next-epoch convergence";
                "signer_retrieval_epoch" => ?signer_retrieval_epoch,
                "error" => ?error,
            );
        }

        // The stake distribution for the synchronized epochs. A long-running follower already has
        // it from a previous `update_stake_distribution` cycle; a freshly started follower has
        // only just recorded the current node snapshot at its recording epoch, so fall back to
        // that so it can bootstrap from a cold start instead of deadlocking.
        let stake_distribution = match self
            .stake_store
            .get_stakes(registration_epoch)
            .await
            .with_context(|| "synchronize_all_signers failed")
            .map_err(SignerRegistrationError::Store)?
        {
            Some(stake_distribution) => stake_distribution,
            None => self
                .stake_store
                .get_stakes(registration_epoch.offset_to_recording_epoch())
                .await
                .with_context(|| "synchronize_all_signers failed")
                .map_err(SignerRegistrationError::Store)?
                .with_context(|| "Follower aggregator did not return any stake distribution")
                .map_err(SignerRegistrationError::Store)?,
        };

        // Per-cycle behaviour: register the leader's next signers at the registration epoch.
        self.synchronize_signers(
            registration_epoch,
            &leader_epoch_settings.next_signers,
            &stake_distribution,
        )
        .await?;

        Ok(())
    }
}

#[async_trait]
impl SignerRegisterer for MithrilSignerRegistrationFollower {
    async fn register_signer(
        &self,
        _epoch: Epoch,
        _signer: &Signer,
    ) -> Result<SignerWithStake, SignerRegistrationError> {
        Err(SignerRegistrationError::RegistrationRoundAlwaysClosedOnFollowerAggregator)
    }

    async fn get_current_round(&self) -> Option<SignerRegistrationRound> {
        None
    }
}

#[async_trait]
impl SignerRegistrationRoundOpener for MithrilSignerRegistrationFollower {
    async fn open_registration_round(
        &self,
        _registration_epoch: Epoch,
        _stake_distribution: StakeDistribution,
    ) -> StdResult<()> {
        Ok(())
    }

    async fn close_registration_round(&self) -> StdResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use chrono::{DateTime, Utc};

    use mithril_common::crypto_helper::GenesisVerifier;
    use mithril_common::entities::{Certificate, CertificateSignature, SignedEntityType};
    use mithril_common::messages::{
        EpochSettingsMessage, MithrilStakeDistributionMessage, SignerMessagePart,
        SignerWithStakeMessagePart, TryFromMessageAdapter,
    };
    use mithril_common::test::{
        builder::{MithrilFixture, MithrilFixtureBuilder},
        double::Dummy,
        double::fake_data,
    };

    use crate::{
        database::{repository::SignerRegistrationStore, test_helper::main_db_connection},
        message_adapters::FromEpochSettingsAdapter,
        services::{
            FakeEpochService, MockLeaderAggregatorClient, MockSignerRecorder,
            MockSignerRegistrationVerifier,
        },
        test::TestLogger,
        test::double::mocks::{MockCertificateRetriever, MockCertificateVerifier, MockStakeStore},
    };

    use super::*;

    use test_utils::*;

    mod test_utils {
        use tokio::sync::RwLock;

        use super::*;

        /// MithrilSignerRegistrationFollowerBuilder is a test builder for [MithrilSignerRegistrationFollower]
        pub struct MithrilSignerRegistrationFollowerBuilder {
            epoch_service: EpochServiceWrapper,
            signer_recorder: Arc<dyn SignerRecorder>,
            signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
            leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,
            stake_store: Arc<dyn StakeStorer>,
            verification_key_store: Arc<dyn VerificationKeyStorer>,
            certificate_retriever: Arc<dyn CertificateRetriever>,
            certificate_verifier: Arc<dyn CertificateVerifier>,
            genesis_verifier: Arc<GenesisVerifier>,
            logger: Logger,
        }

        impl Default for MithrilSignerRegistrationFollowerBuilder {
            fn default() -> Self {
                Self {
                    epoch_service: Arc::new(RwLock::new(FakeEpochService::without_data())),
                    signer_recorder: Arc::new(MockSignerRecorder::new()),
                    signer_registration_verifier: Arc::new(MockSignerRegistrationVerifier::new()),
                    leader_aggregator_client: Arc::new(MockLeaderAggregatorClient::new()),
                    stake_store: Arc::new(MockStakeStore::new()),
                    verification_key_store: Arc::new(SignerRegistrationStore::new(
                        Arc::new(main_db_connection().unwrap()),
                        None,
                    )),
                    certificate_retriever: Arc::new(MockCertificateRetriever::new()),
                    certificate_verifier: Arc::new(MockCertificateVerifier::new()),
                    genesis_verifier: Arc::new(GenesisVerifier::create_deterministic_verifier()),
                    logger: TestLogger::stdout(),
                }
            }
        }

        impl MithrilSignerRegistrationFollowerBuilder {
            pub fn with_epoch_service(self, epoch_service: FakeEpochService) -> Self {
                Self {
                    epoch_service: Arc::new(RwLock::new(epoch_service)),
                    ..self
                }
            }

            pub fn with_signer_recorder(self, signer_recorder: Arc<dyn SignerRecorder>) -> Self {
                Self {
                    signer_recorder,
                    ..self
                }
            }

            pub fn with_signer_registration_verifier(
                self,
                signer_registration_verifier: Arc<dyn SignerRegistrationVerifier>,
            ) -> Self {
                Self {
                    signer_registration_verifier,
                    ..self
                }
            }

            pub fn with_leader_aggregator_client(
                self,
                leader_aggregator_client: Arc<dyn LeaderAggregatorClient>,
            ) -> Self {
                Self {
                    leader_aggregator_client,
                    ..self
                }
            }

            pub fn with_stake_store(self, stake_store: Arc<dyn StakeStorer>) -> Self {
                Self {
                    stake_store,
                    ..self
                }
            }

            pub fn with_certificate_retriever(
                self,
                certificate_retriever: Arc<dyn CertificateRetriever>,
            ) -> Self {
                Self {
                    certificate_retriever,
                    ..self
                }
            }

            pub fn with_certificate_verifier(
                self,
                certificate_verifier: Arc<dyn CertificateVerifier>,
            ) -> Self {
                Self {
                    certificate_verifier,
                    ..self
                }
            }

            pub fn build(self) -> MithrilSignerRegistrationFollower {
                MithrilSignerRegistrationFollower {
                    epoch_service: self.epoch_service,
                    verification_key_store: self.verification_key_store,
                    signer_recorder: self.signer_recorder,
                    signer_registration_verifier: self.signer_registration_verifier,
                    leader_aggregator_client: self.leader_aggregator_client,
                    stake_store: self.stake_store,
                    certificate_retriever: self.certificate_retriever,
                    certificate_verifier: self.certificate_verifier,
                    genesis_verifier: self.genesis_verifier,
                    logger: self.logger,
                }
            }
        }
    }

    /// Build a signed stake-distribution message for `epoch` plus a certificate whose
    /// `NextAggregateVerificationKey` is the AVK of the fixture's signers — i.e. a consistent
    /// pair the trusted bootstrap will accept (the recomputed AVK matches the signed one).
    fn signed_stake_distribution(
        epoch: Epoch,
        fixture: &MithrilFixture,
    ) -> (MithrilStakeDistributionMessage, Certificate) {
        let certificate_hash = "msd-certificate-hash".to_string();
        let mut certificate = fake_data::certificate(certificate_hash.clone());
        certificate.epoch = epoch;
        // A real stake-distribution certificate certifies `MithrilStakeDistribution(epoch)`; the
        // follower binds the verified certificate to that signed entity type before trusting it.
        if let CertificateSignature::MultiSignature(signed_entity_type, _) =
            &mut certificate.signature
        {
            *signed_entity_type = SignedEntityType::MithrilStakeDistribution(epoch);
        }
        certificate.protocol_message.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
        );
        let message = MithrilStakeDistributionMessage {
            epoch,
            signers_with_stake: SignerWithStakeMessagePart::from_signers(
                fixture.signers_with_stake(),
            ),
            hash: "msd-hash".to_string(),
            certificate_hash,
            created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                .unwrap()
                .with_timezone(&Utc),
            protocol_parameters: fixture.protocol_parameters(),
        };

        (message, certificate)
    }

    #[tokio::test]
    async fn open_close_registration_always_succeeds() {
        let signer_registration_follower =
            MithrilSignerRegistrationFollowerBuilder::default().build();
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let stake_distribution = fixture.stake_distribution();

        signer_registration_follower
            .open_registration_round(registration_epoch, stake_distribution)
            .await
            .expect("signer registration round opening should not fail");

        signer_registration_follower
            .close_registration_round()
            .await
            .expect("signer registration round opening should not fail");
    }

    #[tokio::test]
    async fn register_signer_always_fails() {
        let signer_registration_follower =
            MithrilSignerRegistrationFollowerBuilder::default().build();
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();

        signer_registration_follower
            .register_signer(registration_epoch, &signer_to_register)
            .await
            .expect_err("signer registration should always fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_succeeds() {
        let registration_epoch = Epoch(1);
        // The signer-retrieval epoch a fresh follower must bootstrap from the signed stake
        // distribution (= registration epoch - 1).
        let signer_retrieval_epoch = Epoch(0);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        let (stake_distribution_message, certificate) =
            signed_stake_distribution(signer_retrieval_epoch, &fixture);

        // A fresh follower registers the leader's next signers at the registration epoch (per
        // cycle, 5 signers) and then bootstraps the signer-retrieval epoch from the *verified*
        // stake distribution (5 signers) — so 10 records, but only the per-cycle 5 go through the
        // registration verifier.
        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(10);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify_synchronized()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(move |_epoch| Ok(Some(stake_distribution_message.clone())))
                    .times(1);
                Arc::new(aggregator_client)
            })
            .with_certificate_retriever({
                let mut certificate_retriever = MockCertificateRetriever::new();
                certificate_retriever
                    .expect_get_certificate_details()
                    .returning(move |_hash| Ok(certificate.clone()))
                    .times(1);

                Arc::new(certificate_retriever)
            })
            .with_certificate_verifier({
                let mut certificate_verifier = MockCertificateVerifier::new();
                certificate_verifier
                    .expect_verify_certificate_chain()
                    .returning(|_, _| Ok(()))
                    .times(1);

                Arc::new(certificate_verifier)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);
                stake_store
                    .expect_save_stakes()
                    .returning(|_epoch, _stakes| Ok(None))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower.synchronize_all_signers().await.unwrap();
    }

    #[tokio::test]
    async fn synchronize_all_signers_is_non_fatal_when_bootstrap_certificate_does_not_verify() {
        let registration_epoch = Epoch(1);
        let signer_retrieval_epoch = Epoch(0);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        let (stake_distribution_message, certificate) =
            signed_stake_distribution(signer_retrieval_epoch, &fixture);

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(5);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify_synchronized()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(move |_epoch| Ok(Some(stake_distribution_message.clone())))
                    .times(1);
                Arc::new(aggregator_client)
            })
            .with_certificate_retriever({
                let mut certificate_retriever = MockCertificateRetriever::new();
                certificate_retriever
                    .expect_get_certificate_details()
                    .returning(move |_hash| Ok(certificate.clone()))
                    .times(1);

                Arc::new(certificate_retriever)
            })
            .with_certificate_verifier({
                let mut certificate_verifier = MockCertificateVerifier::new();
                certificate_verifier
                    .expect_verify_certificate_chain()
                    .returning(|_, _| Err(anyhow!("invalid certificate")))
                    .times(1);

                Arc::new(certificate_verifier)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);
                // Security: an unverifiable bootstrap certificate must NOT seed any stake.
                stake_store.expect_save_stakes().never();

                Arc::new(stake_store)
            })
            .build();

        // The bootstrap failure is non-fatal: it is logged and the per-cycle registration still
        // runs, so the follower falls back to next-epoch convergence instead of aborting.
        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect("synchronize_all_signers should not fail; the bootstrap failure is non-fatal");
    }

    #[tokio::test]
    async fn synchronize_all_signers_is_non_fatal_when_bootstrap_avk_does_not_match() {
        let registration_epoch = Epoch(1);
        let signer_retrieval_epoch = Epoch(0);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        // Certificate signs a *different* AVK than the one the stake distribution's signers
        // recompute to: a fresh `fake_data::certificate` carries an unrelated fake AVK.
        let (stake_distribution_message, _certificate) =
            signed_stake_distribution(signer_retrieval_epoch, &fixture);
        let mismatched_certificate = fake_data::certificate("msd-certificate-hash");

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(5);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify_synchronized()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(move |_epoch| Ok(Some(stake_distribution_message.clone())))
                    .times(1);
                Arc::new(aggregator_client)
            })
            .with_certificate_retriever({
                let mut certificate_retriever = MockCertificateRetriever::new();
                certificate_retriever
                    .expect_get_certificate_details()
                    .returning(move |_hash| Ok(mismatched_certificate.clone()))
                    .times(1);

                Arc::new(certificate_retriever)
            })
            .with_certificate_verifier({
                let mut certificate_verifier = MockCertificateVerifier::new();
                certificate_verifier
                    .expect_verify_certificate_chain()
                    .returning(|_, _| Ok(()))
                    .times(1);

                Arc::new(certificate_verifier)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);
                // Security: a certificate whose signed AVK does not match the recomputed one must
                // NOT seed any stake.
                stake_store.expect_save_stakes().never();

                Arc::new(stake_store)
            })
            .build();

        // The bootstrap failure is non-fatal: it is logged and the per-cycle registration still
        // runs, so the follower falls back to next-epoch convergence instead of aborting.
        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect("synchronize_all_signers should not fail; the bootstrap failure is non-fatal");
    }

    #[tokio::test]
    async fn synchronize_all_signers_is_non_fatal_when_bootstrap_certificate_is_for_another_epoch() {
        let registration_epoch = Epoch(1);
        let another_epoch = Epoch(7);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        // The certificate verifies and its signed AVK matches the stake distribution's signers, but
        // it certifies `MithrilStakeDistribution(another_epoch)` rather than the requested
        // `signer_retrieval_epoch`. Without the epoch binding this would seed one epoch's signers
        // under another epoch's key; the binding must reject it.
        let (stake_distribution_message, certificate) =
            signed_stake_distribution(another_epoch, &fixture);

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(5);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify_synchronized()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(move |_epoch| Ok(Some(stake_distribution_message.clone())))
                    .times(1);
                Arc::new(aggregator_client)
            })
            .with_certificate_retriever({
                let mut certificate_retriever = MockCertificateRetriever::new();
                certificate_retriever
                    .expect_get_certificate_details()
                    .returning(move |_hash| Ok(certificate.clone()))
                    .times(1);

                Arc::new(certificate_retriever)
            })
            .with_certificate_verifier({
                let mut certificate_verifier = MockCertificateVerifier::new();
                certificate_verifier
                    .expect_verify_certificate_chain()
                    .returning(|_, _| Ok(()))
                    .times(1);

                Arc::new(certificate_verifier)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);
                // Security: a certificate that certifies a different epoch must NOT seed any stake.
                stake_store.expect_save_stakes().never();

                Arc::new(stake_store)
            })
            .build();

        // The bootstrap failure is non-fatal: it is logged and the per-cycle registration still
        // runs, so the follower falls back to next-epoch convergence instead of aborting.
        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect("synchronize_all_signers should not fail; the bootstrap failure is non-fatal");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_one_signer_registration_fails() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(4);
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Err(anyhow!("an error")))
                    .times(1);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify_synchronized()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                // Cold store: the trustless bootstrap runs first; return no stake distribution so
                // it is a non-fatal no-op and the test exercises the per-cycle failure path.
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(|_epoch| Ok(None))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_epoch_service_update_next_signers_fails() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let stake_distribution = fixture.stake_distribution();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();

        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_epoch_service({
                let mut epoch_service = FakeEpochService::without_data();
                epoch_service.toggle_errors(false, false, true);

                epoch_service
            })
            .with_signer_recorder({
                let mut signer_recorder = MockSignerRecorder::new();
                signer_recorder
                    .expect_record_signer_registration()
                    .returning(|_| Ok(()))
                    .times(5);

                Arc::new(signer_recorder)
            })
            .with_signer_registration_verifier({
                let mut signer_registration_verifier = MockSignerRegistrationVerifier::new();
                signer_registration_verifier
                    .expect_verify_synchronized()
                    .returning(|signer, _| Ok(SignerWithStake::from_signer(signer.to_owned(), 123)))
                    .times(5);

                Arc::new(signer_registration_verifier)
            })
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                // Cold store: the trustless bootstrap runs first; return no stake distribution so
                // it is a non-fatal no-op and the test exercises the per-cycle failure path.
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(|_epoch| Ok(None))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Ok(Some(stake_distribution.clone())))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_fetching_epoch_settings_fails() {
        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Err(anyhow!("an error")))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }

    #[tokio::test]
    async fn synchronize_all_signers_fails_if_fetching_stakes_fails() {
        let registration_epoch = Epoch(1);
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .disable_signers_certification()
            .build();
        let signers = fixture.signers();
        let epoch_settings_message = FromEpochSettingsAdapter::try_adapt(EpochSettingsMessage {
            epoch: registration_epoch,
            current_signers: SignerMessagePart::from_signers(signers.clone()),
            next_signers: SignerMessagePart::from_signers(signers),
            ..EpochSettingsMessage::dummy()
        })
        .unwrap();
        let signer_registration_follower = MithrilSignerRegistrationFollowerBuilder::default()
            .with_leader_aggregator_client({
                let mut aggregator_client = MockLeaderAggregatorClient::new();
                aggregator_client
                    .expect_retrieve_epoch_settings()
                    .returning(move || Ok(Some(epoch_settings_message.clone())))
                    .times(1);
                // Cold store: the trustless bootstrap runs first; return no stake distribution so
                // it is a non-fatal no-op and the test exercises the per-cycle failure path.
                aggregator_client
                    .expect_retrieve_mithril_stake_distribution()
                    .returning(|_epoch| Ok(None))
                    .times(1);

                Arc::new(aggregator_client)
            })
            .with_stake_store({
                let mut stake_store = MockStakeStore::new();
                stake_store
                    .expect_get_stakes()
                    .returning(move |_epoch| Err(anyhow!("an error")))
                    .times(1);

                Arc::new(stake_store)
            })
            .build();

        signer_registration_follower
            .synchronize_all_signers()
            .await
            .expect_err("synchronize_all_signers should fail");
    }
}
