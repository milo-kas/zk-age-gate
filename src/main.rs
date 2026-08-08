//! # The Protocol Coordinator (Console & Network)
//! Serves as the interface and network wire for the demo,
//! it routes cryptographic packages between the isolated Actors
//!
//! **Architectural Assumption**: all communication occurs over an authenticated and encrypted channel

use issuer::Issuer;
use prover::Prover;
use verifier::Verifier;

#[tokio::main]
async fn main() {
    println!("[Protocol Coordinator] Starting protocol demo...");

    // Initialise Isolated Actors
    let issuer = Issuer::new();
    let mut prover = Prover::new();

    // Prover packages the age request ready for the trusted Issuer
    let age_request = prover.create_age_request("SOME_ID"); // TODO: randomise the ID

    println!("[Protocol Coordinator] Routing Age Request to Issuer...");

    // Trust Boundary - Prover requests CredentialPackage from Issuer
    let credential_package = issuer.issue_credential(age_request);

    println!("[Protocol Coordinator] Routing Credential Package to Prover...");

    // Trust Boundary - Issuer sends CredentialPackage to Prover
    prover.receive_credential_package(credential_package);

    // dummy threshold TODO: Verifier communicates the threshold
    let age_threshold = 18;

    let proof_package = prover.generate_proof_package(age_threshold);

    println!("[Protocol Coordinator] Routing Proof Package to Verifier...");

    println!("{:#?}", proof_package);

    let verifier = Verifier::new(issuer.get_public_key());

    let is_valid = verifier.verify_proof_package(&proof_package);
    println!("Proof valid: {}", is_valid);

    // TODO: return access granted back to prover
}
