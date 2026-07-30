//! The Protocol Coordinator (Console) that provides the demo interface and coordinates the protocol

use issuer::Issuer;

use types::AgeRequest;

use ark_bn254::Fr;

fn main() {
    println!("[Console] Starting protocol demo...");

    // Initialise Issuer (Trusted Authority)
    let issuer = Issuer::new();

    // dummy pk_p
    let pk_p = Fr::from(1234);

    println!("[Prover (INTERNAL)] Packaging AgeRequest...");

    // Package the age request for Issuer
    let age_request = AgeRequest {
        pk_p,
        id: "SOME_ID".to_string() // TODO: randomise the ID
    };

    println!("[Prover (INTERNAL)] Sending credential request to Issuer...");

    // Trust Boundary - Prover requests CredentialPackage from Issuer
    // Trust Boundary - Issuer sends CredentialPackage to Prover
    let credential_package = issuer.issue_credential(age_request);

    println!("[Prover (INTERNAL)] Credential Package received!");
    println!("{:#?}", credential_package);
}
