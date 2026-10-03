use std::collections::HashMap;

use issuer::Issuer;
use prover::Prover;
use verifier::Verifier;

use types::AccessStatus;

#[test]
fn grants_access_when_age_meets_threshold() {
    let id = "SOME_ID";

    let age = 20;
    let threshold = 18;

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

    // Verify Proof Package
    let access_decision: AccessStatus = verifier.verify_proof_package(&proof_package);

    assert_eq!(
        access_decision,
        AccessStatus::Granted,
        "Should grant access for valid proof"
    );
}
