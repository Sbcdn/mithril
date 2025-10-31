use super::*;

pub struct Initializer {
    pub stake: Stake,
    pub parameters: Parameters,
    pub bls_signing_key: BlsSigningKey,
    pub bls_public_key: BlsVerificationKeyProofOfPossession,
    #[cfg(feature = "future_snark")]
    pub schnorr_signing_key: Option<SchnorrSigningKey>,
    #[cfg(feature = "future_snark")]
    pub schnorr_public_key: Option<SchnorrVerificationKeyProofOfPossession>,
}

impl Initializer {
    pub fn new(
        stake: Stake,
        parameters: Parameters,
        bls_signing_key: BlsSigningKey,
        bls_public_key: BlsVerificationKeyProofOfPossession,
        #[cfg(feature = "future_snark")] schnorr_signing_key: Option<SchnorrSigningKey>,
        #[cfg(feature = "future_snark")] schnorr_public_key: Option<
            SchnorrVerificationKeyProofOfPossession,
        >,
    ) -> Self {
        Self {
            stake,
            parameters,
            bls_signing_key,
            bls_public_key,
            #[cfg(feature = "future_snark")]
            schnorr_signing_key,
            #[cfg(feature = "future_snark")]
            schnorr_public_key,
        }
    }

    pub fn into_signer(self) -> Signer {
        /* Signer::new(
            self.stake,
            self.parameters,
            self.bls_signing_key,
            self.bls_public_key,
            #[cfg(feature = "future_snark")]
            self.schnorr_signing_key,
            #[cfg(feature = "future_snark")]
            self.schnorr_signing_key,
            #[cfg(feature = "future_snark")]
            self.schnorr_public_key,
        ) */
        todo!("Implement Signer conversion")
    }
}
