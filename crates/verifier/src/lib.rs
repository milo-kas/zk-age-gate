//! Defines the Verifier Actor

use types::{colored::Colorize, verifier_log, AccessStatus, ProofPackage};

use std::fs::File;
use std::io::BufReader;
// Ark
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_snark::SNARK;
// Signature
use ed25519_dalek::{Verifier as _, VerifyingKey};

use getrandom::{
    SysRng,
    rand_core::{Rng, UnwrapErr},
};
use types::AccessStatus::{Granted, Denied};

/// Verifier acts as the relaying-party checking the proof
pub struct Verifier {
    age_threshold: u8,
    trusted_issuer_pk: VerifyingKey,
    current_nonce: Option<u64>,
}

impl Verifier {
    /// Instantiate a new Verifier
    pub fn new(age_threshold: u8, trusted_issuer_pk: VerifyingKey) -> Self {
        verifier_log!("Initialising...");

        Self {
            age_threshold,
            trusted_issuer_pk,
            current_nonce: None,
        }
    }

    /// Getter for age threshold policy (for Prover)
    pub fn get_age_policy(&self) -> u8 {
        verifier_log!(
            "Providing age requirement policy: age >= {}...",
            self.age_threshold
        );
        self.age_threshold
    }

    /// Generate a nonce for the next proof package
    pub fn issue_nonce(&mut self) -> u64 {
        let mut csprng = UnwrapErr(SysRng);
        let nonce = csprng.next_u64();

        self.current_nonce = Some(nonce);
        verifier_log!("Issued nonce: {}", nonce);

        nonce
    }

    pub fn verify_proof_package(&mut self, proof_package: &ProofPackage) -> AccessStatus {
        // Enforce active nonce and consume it immediately
        let nonce = match self.current_nonce.take() {
            Some(c) => c,
            None => {
                eprintln!("[Verifier (INTERNAL)] No active nonce found! Aborting...");
                return Denied;
            }
        };

        let commitment_bytes = proof_package.commitment.into_bigint().to_bytes_le();

        // Verify whether the Issuer actually signed the commitment
        if self
            .trusted_issuer_pk
            .verify(&commitment_bytes, &proof_package.signature)
            .is_ok()
        {
            verifier_log!("Valid Commitment Signature!");
        } else {
            eprintln!("[Verifier (INTERNAL)] Invalid Commitment Signature! Aborting...");
            return Denied;
        }

        // Verify whether the ZK proof holds up from public inputs
        let public_inputs = vec![
            Fr::from(self.age_threshold), // Enforce own threshold
            proof_package.commitment,     // Signed commitment
            proof_package.pk_p,           // Prover's Public Key
            Fr::from(nonce),
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
        if Groth16::<Bn254>::verify_with_processed_vk(
            &prep_vk,
            &public_inputs,
            &proof_package.proof,
        )
        .unwrap_or(false)
        {
            verifier_log!("Valid Proof!");
            Granted // Both Signature and Proof are valid
        } else {
            eprintln!("[Verifier (INTERNAL)] Invalid Proof! Aborting...");
            Denied
        }
    }
}
