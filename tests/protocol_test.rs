use std::collections::HashMap;

use issuer::Issuer;
use prover::Prover;
use verifier::Verifier;

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};

use types::{AccessStatus, CredentialPackage};

fn run_protocol(age: u8, threshold: u8, id: &str) -> AccessStatus {
    let identity_records = HashMap::from([(id.to_string(), age)]);

    // init
    let issuer = Issuer::new(identity_records);
    let mut prover = Prover::new(id);
    let mut verifier = Verifier::new(threshold, issuer.get_public_key());

    // Request credential from issuer
    let credential = issuer
        .issue_credential(prover.create_age_request())
        .expect("Should succeed to issue credential");

    prover.receive_credential_package(credential);

    // Generate Proof Package
    let proof_package =
        prover.generate_proof_package(verifier.get_age_policy(), verifier.issue_nonce());

    // Verify Proof Package and return access decision
    verifier.verify_proof_package(&proof_package)
}

#[test]
fn grants_access_when_age_meets_threshold() {
    let id = "SOME_ID";

    let age = 20;
    let threshold = 18;

    let access_decision = run_protocol(age, threshold, id);

    assert_eq!(
        access_decision,
        AccessStatus::Granted,
        "Should grant access for valid proof"
    );
}

#[test]
fn denies_access_when_age_is_below_threshold() {
    let id = "SOME_ID";

    let age = 10;
    let threshold = 18;

    let access_decision = run_protocol(age, threshold, id);

    assert_eq!(
        access_decision,
        AccessStatus::Denied,
        "Should deny access for invalid proof (age < threshold)"
    );
}

#[test]
fn denies_access_when_underage_prover_forges_over_threshold_commitment() {
    let id = "SOME_ID";

    let real_age = 16; // Underage in the Issuer's records
    let forged_age = 20; // Forged to satisfy the circuit (>= threshold)
    let threshold = 18;

    let identity_records = HashMap::from([(id.to_string(), real_age)]);

    // init
    let issuer = Issuer::new(identity_records);
    let mut prover = Prover::new(id);
    let mut verifier = Verifier::new(threshold, issuer.get_public_key());

    // Request the legitimate (underage) credential from the issuer
    let age_request = prover.create_age_request();
    let pk_p = age_request.pk_p;
    let credential = issuer
        .issue_credential(age_request)
        .expect("Should succeed to issue credential");

    // Attack: recompute the commitment for the forged age so the circuit constraints
    // (Poseidon(forged_age, salt, pk_p) and forged_age >= threshold) hold, then attach
    // the issuer's real signature from the age-16 credential
    let forged_commitment = Poseidon::<Fr>::new_circom(3)
        .expect("Failed to initialise Poseidon")
        .hash(&[Fr::from(forged_age), credential.salt, pk_p])
        .expect("Poseidon hash failed");

    prover.receive_credential_package(CredentialPackage {
        age: forged_age,
        salt: credential.salt,
        commitment: forged_commitment,
        signature: credential.signature,
    });

    // The Prover produces a mathematically valid Groth16 proof for forged_age >= threshold
    let proof_package =
        prover.generate_proof_package(verifier.get_age_policy(), verifier.issue_nonce());

    // The Verifier rejects because the issuer's signature does not cover the forged commitment
    let access_decision = verifier.verify_proof_package(&proof_package);

    assert_eq!(
        access_decision,
        AccessStatus::Denied,
        "Should deny access when the issuer signature does not cover the forged commitment"
    );
}
