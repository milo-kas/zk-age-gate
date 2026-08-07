//! # The Protocol Coordinator (Console & Network)
//! Serves as the interface and network wire for the demo,
//! it routes cryptographic packages between the isolated Actors
//!
//! **Architectural Assumption**: all communication occurs over an authenticated and encrypted channel

use issuer::Issuer;
use prover::Prover;
use std::fs::File;
use std::io::BufReader;

// todo: Refactor to verifier
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_snark::SNARK;
use ed25519_dalek::Verifier;

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

    // TODO: Refactor following to Verifier crate

    let commitment_bytes = proof_package.commitment.into_bigint().to_bytes_le();
    let issuer_pub_key = issuer.get_public_key();

    // Verify whether the Issuer actually signed the commitment
    if issuer_pub_key
        .verify(&commitment_bytes, &proof_package.signature)
        .is_ok()
    {
        println!("[Verifier (INTERNAL)]: Valid Commitment Signature!");
    } else {
        eprintln!("[Verifier (INTERNAL)]: Invalid Commitment Signature! Aborting...");
        // return false
    }

    // Verify whether the ZK proof holds up from public inputs
    let public_inputs = vec![
        Fr::from(age_threshold),  // Enforce own threshold
        proof_package.commitment, // Signed commitment
        proof_package.pk_p,       // Prover's Public Key
    ];

    // Path to .zkey
    let zkey_path = "circuits/build/age_gate.zkey".to_string();

    // TODO: Verifier MUST NOT read from a .zkey file -- extract and store only verification key
    // Read the Proving Key file to extract its inner Verifying Key
    let file = File::open(&zkey_path).expect("Failed to open zkey file");
    let mut reader = BufReader::new(file);
    let (pk, _) = ark_circom::read_zkey(&mut reader).expect("Failed to read zkey");

    // Prepare verifying key for circuit verification
    let prep_vk = prepare_verifying_key(&pk.vk);

    // Verify the proof with public inputs AND
    // whether these abide by the rules defined by the Verifying Key
    if Groth16::<Bn254>::verify_with_processed_vk(&prep_vk, &public_inputs, &proof_package.proof)
        .unwrap_or(false)
    {
        println!("[Verifier (INTERNAL)]: Valid Proof!");
    } else {
        eprintln!("[Verifier (INTERNAL)]: Invalid Proof! Aborting...");
        // return false
    }

    // TODO: return access granted back to prover
}
