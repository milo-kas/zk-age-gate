//! # The Protocol Coordinator (Console & Network)
//! Serves as the interface and network wire for the demo,
//! it routes cryptographic packages between the isolated Actors
//!
//! **Architectural Assumption**: all communication occurs over an authenticated and encrypted channel

use issuer::Issuer;
use prover::Prover;
use verifier::Verifier;

use types::{colored::Colorize, coord_log};

#[tokio::main]
async fn main() {
    coord_log!("Starting protocol demo...");

    // Initialise Isolated Actors
    let issuer = Issuer::new();
    let mut prover = Prover::new();

    // Prover packages the age request ready for the trusted Issuer
    let age_request = prover.create_age_request("SOME_ID"); // TODO: randomise the ID

    coord_log!("Routing Age Request to Issuer...");

    // Trust Boundary - Prover requests CredentialPackage from Issuer
    let credential_package = issuer.issue_credential(age_request);

    coord_log!("Routing Credential Package to Prover...");

    // Trust Boundary - Issuer sends CredentialPackage to Prover
    prover.receive_credential_package(credential_package);

    // Initialise Verifier with age threshold
    let verifier = Verifier::new(20, issuer.get_public_key());

    let age_threshold = verifier.get_age_threshold();
    coord_log!("Verifier Request for age >= {}", age_threshold);

    // Prover generates proof that meets age_threshold
    let proof_package = prover.generate_proof_package(age_threshold);

    coord_log!("Routing Proof Package to Verifier...");

    println!("{:#?}", proof_package);

    let is_valid = verifier.verify_proof_package(&proof_package);
    coord_log!("Proof valid: {}", is_valid);

    // TODO: return access granted back to prover
}
