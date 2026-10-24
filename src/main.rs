//! # The Protocol Coordinator (Console & Network)
//! Serves as the interface and network wire for the demo,
//! it routes cryptographic packages between the isolated Actors
//!
//! **Architectural Assumption**: all communication occurs over an authenticated and encrypted channel

use issuer::Issuer;
use prover::Prover;
use std::collections::HashMap;
use verifier::Verifier;

use types::{DoB, colored::Colorize, coord_log};

fn main() {
    coord_log!("Starting protocol demo...");

    // Initialise Isolated Actors
    let issuer = Issuer::new(setup_identity_records());
    let mut prover = Prover::new(String::from("SOME_ID"));

    // Prover packages the age request ready for the trusted Issuer
    let age_request = prover.create_age_request();

    coord_log!("Routing Age Request to Issuer...");

    // Trust Boundary - Prover requests CredentialPackage from Issuer
    let credential_package = issuer
        .issue_credential(age_request)
        .expect("Failed to issue credential package:");

    coord_log!("Routing Credential Package to Prover...");

    // Trust Boundary - Issuer sends CredentialPackage to Prover
    prover.receive_credential_package(credential_package);

    // Initialise Verifier with age threshold
    let mut verifier = Verifier::new(20, issuer.public_key());

    let verifier_challenge = verifier.issue_challenge();
    coord_log!("Routing DoB cutoff epoch & nonce to Prover...");

    // Prover generates proof that meets verifier_challenge
    let proof_package = prover.generate_proof_package(verifier_challenge);

    coord_log!("Routing Proof Package to Verifier...");

    println!("{:#?}", proof_package);

    let access_decision = verifier.verify_proof_package(&proof_package);

    // Return access decision back to Prover
    coord_log!("Routing Proof Validity to Prover...");
    prover.receive_access_decision(access_decision);
}

fn setup_identity_records() -> HashMap<String, DoB> {
    let mut identity_records = HashMap::new();

    let dob = DoB {
        year: 2005,
        month: 1,
        day: 1,
    };

    identity_records.insert("SOME_ID".to_string(), dob);

    identity_records
}
