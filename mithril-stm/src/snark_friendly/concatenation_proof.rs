use super::*;

pub struct BlakeDigest;

impl Digest for BlakeDigest {
    fn digest(data: &[u8]) -> Vec<u8> {
        todo!("Implement Blake digest")
    }
}

pub struct ConcatenationSingleSignature {
    pub signature: BlsSignature,
    pub lottery_indices: Vec<u64>,
}

pub struct ConcatenationProofSingleSignatureGenerator {
    pub signer_index: SignerIndex,
    pub stake: Stake,
    pub parameters: Parameters,
    pub bls_crypto_signer: BlsCryptoSigner,
    pub key_registration: MerkleTree<BlakeDigest>,
}

impl ProofSystemSingleSignatureGenerator for ConcatenationProofSingleSignatureGenerator {
    type ProofSystemSingleSignature = ConcatenationSingleSignature;

    fn create_individual_signature(
        &self,
        message: &[u8],
    ) -> StdResult<Self::ProofSystemSingleSignature> {
        // Signer registration => Reveal of signer registration with Merkle proof
        todo!("Implement concatenation proof individual signature generation")
    }
}

pub struct ConcatenationProof {}

pub struct ConcatenationProofGenerator {
    pub parameters: Parameters,
    pub concatenation_proof_individual_signature_generator:
        ConcatenationProofSingleSignatureGenerator,
    pub key_registration: MerkleTree<BlakeDigest>,
}

impl ConcatenationProofGenerator {
    pub fn new(parameters: &Parameters, key_registrations: &KeyRegistration) -> Self {
        todo!("Implement new for ConcatenationProofGenerator")
    }

    pub fn create_concatenation_proof(
        &self,
        message: &[u8],
        signatures: &[SingleSignature],
    ) -> StdResult<ConcatenationProof> {
        // Implement concatenation proof creation logic here
        todo!("Implement concatenation proof creation")
    }
}
