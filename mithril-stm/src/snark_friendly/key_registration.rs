use super::*;

pub struct KeyRegistration {
    signer_registrations: Vec<SignerRegistration>,
}

impl KeyRegistration {
    pub fn new(signer_registrations: Vec<SignerRegistration>) -> Self {
        Self {
            signer_registrations,
        }
    }

    pub fn into_merkle_tree<D: Digest>(self) -> MerkleTree<D> {
        todo!("Implement conversion of KeyRegistration into MerkleTree")
    }

    #[cfg(feature = "future_snark")]
    // In case we need it for reccursive snarks
    pub fn into_pedersen_commitment(self) -> PedersenCommitment {
        todo!("Implement conversion of KeyRegistration into PedersenCommitment")
    }
}
