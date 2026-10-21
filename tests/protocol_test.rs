use ark_bn254::Fr;
use chrono::NaiveDate;
use issuer::Issuer;
use light_poseidon::{Poseidon, PoseidonHasher};
use prover::Prover;
use std::collections::HashMap;
use verifier::Verifier;

use types::{AccessStatus, CredentialPackage, DoB, schema};

/// Defined current date for the test
pub const fn test_reference_date() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 1, 1).expect("Valid epoch date")
}

fn run_protocol(dob: DoB, threshold: u8, id: &str) -> AccessStatus {
    let identity_records = HashMap::from([(id.to_string(), dob)]);

    // init
    let issuer = Issuer::new(identity_records);
    let mut prover = Prover::new(id);
    let mut verifier = Verifier::new(threshold, issuer.public_key());

    // Request credential from issuer
    let credential = issuer
        .issue_credential(prover.create_age_request())
        .expect("Should succeed to issue credential");

    prover.receive_credential_package(credential);

    // Generate Proof Package
    let proof_package =
        prover.generate_proof_package(verifier.issue_challenge_at(test_reference_date()));

    // Verify Proof Package and return access decision
    verifier.verify_proof_package(&proof_package)
}

#[test]
fn grants_access_when_age_meets_threshold() {
    let id = "SOME_ID";

    let dob = DoB {
        year: 2000,
        month: 10,
        day: 20,
    };

    let threshold = 18;

    let access_decision = run_protocol(dob, threshold, id);

    assert_eq!(
        access_decision,
        AccessStatus::Granted,
        "Should grant access for valid proof"
    );
}

#[test]
fn denies_access_when_age_is_below_threshold() {
    let id = "SOME_ID";

    let dob = DoB {
        year: 2020,
        month: 10,
        day: 20,
    };
    let threshold = 18;

    let access_decision = run_protocol(dob, threshold, id);

    assert_eq!(
        access_decision,
        AccessStatus::Denied,
        "Should deny access for invalid proof (age < threshold)"
    );
}

#[test]
fn denies_access_when_underage_prover_forges_over_threshold_commitment() {
    let id = "SOME_ID";

    let real_dob = DoB {
        year: 2010,
        month: 10,
        day: 20,
    }; // Underage in the Issuer's records
    let forged_dob = DoB {
        year: 2000,
        month: 10,
        day: 20,
    }; // Forged to satisfy the circuit (dobEpoch <= thresholdEpoch)
    let threshold = 18;

    let identity_records = HashMap::from([(id.to_string(), real_dob)]);

    // init
    let issuer = Issuer::new(identity_records);
    let mut prover = Prover::new(id);
    let mut verifier = Verifier::new(threshold, issuer.public_key());

    // Request the legitimate (underage) credential from the issuer
    let age_request = prover.create_age_request();
    let pk_p = age_request.pk_p;
    let credential = issuer
        .issue_credential(age_request)
        .expect("Should succeed to issue credential");

    let forged_dob_epoch = forged_dob.to_days_since_epoch();

    // Attack: recompute the commitment for the forged DoB so the circuit constraints
    // (Poseidon(forged_dob_epoch, salt, pk_p) and forged_dob_epoch <= threshold_epoch) hold,
    // then attach the issuer's real signature from the underage credential
    let forged_commitment = Poseidon::<Fr>::new_circom(3)
        .expect("Failed to initialise Poseidon")
        .hash(&[Fr::from(forged_dob_epoch), credential.salt, pk_p])
        .expect("Poseidon hash failed");

    prover.receive_credential_package(CredentialPackage {
        schema_version: schema::VERSION,
        dob_epoch: forged_dob_epoch,
        salt: credential.salt,
        commitment: forged_commitment,
        signature: credential.signature,
    });

    // The Prover produces a mathematically valid Groth16 proof for forged_dob_epoch <= threshold_epoch
    let proof_package =
        prover.generate_proof_package(verifier.issue_challenge_at(test_reference_date()));

    // The Verifier rejects because the issuer's signature does not cover the forged commitment
    let access_decision = verifier.verify_proof_package(&proof_package);

    assert_eq!(
        access_decision,
        AccessStatus::Denied,
        "Should deny access when the issuer signature does not cover the forged commitment"
    );
}
