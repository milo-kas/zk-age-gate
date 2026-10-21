//! Defines the Verifier Actor

use types::{
    AccessStatus, DoB, ProofPackage, VerifierChallenge, colored::Colorize, schema, verifier_log,
};

use std::fs::File;
use std::io::BufReader;
// Ark
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_snark::SNARK;
use ark_std::rand::{RngCore, rngs::OsRng};
// Signature
use ed25519_dalek::{Verifier as _, VerifyingKey};

// Date
use chrono::{NaiveDate, Utc};

use types::AccessStatus::{Denied, Granted};

/// Verifier acts as the Relying Party verifying proofs to enforce access
/// decisions for downstream business logic
pub struct Verifier {
    age_threshold: u8,
    trusted_issuer_pk: VerifyingKey,
    current_challenge: Option<VerifierChallenge>,
}

impl Verifier {
    /// Instantiate a new Verifier
    pub fn new(age_threshold: u8, trusted_issuer_pk: VerifyingKey) -> Self {
        verifier_log!("Initialising...");

        Self {
            age_threshold,
            trusted_issuer_pk,
            current_challenge: None,
        }
    }

    /// Getter for current age policy (informational only)
    pub fn age_policy(&self) -> u8 {
        self.age_threshold
    }

    /// Issue challenge using current UTC date
    pub fn issue_challenge(&mut self) -> VerifierChallenge {
        let today = Utc::now().date_naive();
        self.issue_challenge_internal(today)
    }

    /// Deterministic challenge generation for test environment only
    #[cfg(any(test, feature = "test-utils"))]
    pub fn issue_challenge_at(&mut self, reference_date: NaiveDate) -> VerifierChallenge {
        self.issue_challenge_internal(reference_date)
    }

    /// Private helper: Generate a nonce & lock DoB cutoff for the current session against
    /// an explicit reference date
    fn issue_challenge_internal(&mut self, reference_date: NaiveDate) -> VerifierChallenge {
        // Session nonce
        let mut rng = OsRng;
        let nonce = rng.next_u64();

        verifier_log!("Issued nonce: {}", nonce);

        // Session DoB cutoff
        let cutoff_dob = DoB::calculate_dob_cutoff(reference_date, self.age_threshold);
        let threshold_epoch = cutoff_dob.to_days_since_epoch();

        verifier_log!("Issued cutoff epoch: {}", threshold_epoch);
        verifier_log!(
            "Cutoff: {:04}-{:02}-{:02}",
            cutoff_dob.year,
            cutoff_dob.month,
            cutoff_dob.day
        );

        let challenge = VerifierChallenge {
            nonce,
            threshold_epoch,
        };

        self.current_challenge = Some(challenge);

        challenge
    }

    pub fn verify_proof_package(&mut self, proof_package: &ProofPackage) -> AccessStatus {
        // Enforce active nonce and threshold epoch and consume them immediately
        let challenge = match self.current_challenge.take() {
            Some(c) => c,
            None => {
                eprintln!("[Verifier (INTERNAL)] No active challenge found! Aborting...");
                return Denied;
            }
        };

        let expected_signed_payload =
            schema::bind_commitment_with_version(&proof_package.commitment);

        // Verify whether the schema version aligns and that the Issuer signed the payload
        if self
            .trusted_issuer_pk
            .verify(&expected_signed_payload, &proof_package.signature)
            .is_ok()
        {
            verifier_log!("Valid Commitment & Schema Version Signature!");
        } else {
            eprintln!("[Verifier (INTERNAL)] Invalid Signature or Schema Mismatch! Aborting...");
            return Denied;
        }

        // Verify whether the ZK proof holds up from public inputs
        let public_inputs = vec![
            Fr::from(challenge.threshold_epoch), // Enforce current active DoB cutoff epoch
            proof_package.commitment,            // Signed commitment
            proof_package.pk_p,                  // Prover's public key (pk)
            Fr::from(challenge.nonce),
        ];

        // Path to .zkey
        let zkey_path = "circuits/build/age_gate.zkey".to_string();

        // TODO: Verifier MUST NOT read from a .zkey file -- extract and store only verification key
        // Read the Proving Key file to extract its inner Verifying Key
        let file = File::open(&zkey_path).expect("Failed to open zkey file");
        let mut reader = BufReader::new(file);
        let (proving_key, _) = ark_circom::read_zkey(&mut reader).expect("Failed to read zkey");

        // Prepare verifying key for circuit verification
        let prep_vk = prepare_verifying_key(&proving_key.vk);

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
