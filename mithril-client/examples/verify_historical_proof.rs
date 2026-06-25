//! Verify a HISTORICAL Cardano transaction inclusion proof — one fetched with
//! `up_to_block_number` so it anchors to a chosen past certificate, not the latest tip —
//! using the production `mithril-client` verification path.
//!
//! Env: AGGREGATOR_ENDPOINT, GENESIS_VERIFICATION_KEY, PROOF_JSON (path to the proof message
//! JSON as returned by `/proof/cardano-transaction?...&up_to_block_number=B`).

use mithril_client::{CardanoTransactionsProofs, ClientBuilder, MessageBuilder};

#[allow(deprecated)] // `ClientBuilder::aggregator` keeps the example short; fine for a demo.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = std::env::var("AGGREGATOR_ENDPOINT")?;
    let genesis = std::env::var("GENESIS_VERIFICATION_KEY")?;
    let proof_path = std::env::var("PROOF_JSON")?;

    let proofs: CardanoTransactionsProofs =
        serde_json::from_str(&std::fs::read_to_string(&proof_path)?)?;
    println!("proof anchors to certificate: {}", proofs.certificate_hash);

    // (1) Reconstruct the Merkle root from the inclusion proof (production verify).
    let verified = proofs.verify()?;

    // (2) Verify the certificate chain up to the genesis key.
    let client = ClientBuilder::aggregator(&endpoint, &genesis).build()?;
    let certificate = client.certificate().verify_chain(&proofs.certificate_hash).await?;
    println!(
        "certificate chain verified to genesis: hash={} epoch={}",
        certificate.hash, certificate.epoch
    );

    // (3) Bind: the proof's reconstructed root must equal the root this certificate signed.
    let message =
        MessageBuilder::new().compute_cardano_transactions_proofs_message(&certificate, &verified);
    if certificate.match_message(&message) {
        println!(
            "\nVERIFIED: certificate {} (a genesis-anchored Mithril certificate) signs the \
             reconstructed Merkle root of this proof.",
            certificate.hash
        );
        println!("certified transactions: {:?}", verified.certified_transactions());
        Ok(())
    } else {
        anyhow::bail!("certificate does NOT match the verified proof message")
    }
}
