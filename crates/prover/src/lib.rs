//! Defines the Prover Actor

use types::{colored::Colorize, prover_log, AccessStatus, AgeRequest, CredentialPackage, ProofPackage};

// ARK & Prover Frameworks
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use circom_prover::{CircomProver, prover::ProofLib, witness::WitnessFn};
use witnesscalc_adapter::witness;

// Other Utilities
use num_bigint::{BigInt, Sign};
use std::collections::HashMap;

witness!(age_gate);

use getrandom::{
    SysRng,
    rand_core::{Rng, UnwrapErr},
};

/// Finite Field Element Extension
pub trait FrExt {
    /// Converts a Field Element (Fr) to a numerical base-10 string, maintaining precision
    ///
    /// Formatted for JSON serialisation for the Circom C++ witness generator
    fn to_base10_string(&self) -> String;
}

impl FrExt for Fr {
    fn to_base10_string(&self) -> String {
        let bytes = self.into_bigint().to_bytes_le();

        BigInt::from_bytes_le(Sign::Plus, &bytes).to_string()
    }
}

// TODO: verifier sends age threshold request

/// Prover acts as the end-user proving their age is above a given threshold
pub struct Prover {
    // Private storage (prover key and credential package)
    pk_p: Fr,
    credential_package: Option<CredentialPackage>,
}

impl Prover {
    /// Instantiate a new Prover
    pub fn new() -> Self {
        prover_log!("Initalising...");

        let mut csprng = UnwrapErr(SysRng);
        Self {
            pk_p: Fr::from(csprng.next_u64()),
            credential_package: None,
        }
    }

    /// Package the Age Request for the Issuer
    pub fn create_age_request(&self, id: &str) -> AgeRequest {
        prover_log!("Packaging AgeRequest...");

        let age_request = AgeRequest {
            pk_p: self.pk_p,
            id: id.to_string(),
        };

        age_request
    }

    /// Take the Credential Package issued from the Issuer
    pub fn receive_credential_package(&mut self, package: CredentialPackage) {
        prover_log!("Credential Package received!");
        prover_log!("Storing Credential Package ...");
        self.credential_package = Some(package);
    }

    /// Generate Proof Package (with native C++) for the Verifier
    pub fn generate_proof_package(&self, age_threshold: u8, nonce: u64) -> ProofPackage {
        let credential_package = self
            .credential_package
            .as_ref()
            .expect("Credential Package not found");

        prover_log!("Formatting inputs for native C++ witness generation...");

        // Format field elements as precise base-10 strings
        let salt_str = credential_package.salt.to_base10_string();
        let comm_str = credential_package.commitment.to_base10_string();
        let pk_str = self.pk_p.to_base10_string();

        // Ages naturally convert to string
        let age_str = credential_package.age.to_string();
        let threshold_age_str = age_threshold.to_string();

        let nonce_str = nonce.to_string();

        // HashMap inputs matching Circom circuit signal schema
        let inputs = HashMap::from([
            // Private Inputs
            ("providedAge".to_string(), vec![age_str]),
            ("providedSalt".to_string(), vec![salt_str]),
            // Public Inputs
            ("thresholdAge".to_string(), vec![threshold_age_str]),
            ("issuerCommitment".to_string(), vec![comm_str]),
            ("pk_p".to_string(), vec![pk_str]),
            ("nonce".to_string(), vec![nonce_str]),
        ]);

        // Serialise to JSON object
        let input_str = serde_json::to_string(&inputs).expect("Failed to serialise circuit inputs");

        // Generate the Proof with the CircomProver and extract the inner proof field
        // Path to .zkey
        let zkey_path = "circuits/build/age_gate.zkey".to_string();

        prover_log!("Executing native C++ witness and calculating Groth16 proof...");

        // Circom wrapper
        let circom_proof = CircomProver::prove(
            // Use Rust Arkworks library to calculate Groth16 proof in Bn254
            ProofLib::Arkworks,
            // Use the native C++ witness
            WitnessFn::WitnessCalc(age_gate_witness),
            // Inputs
            input_str,
            // Path to Proving key
            zkey_path.clone(),
        )
        .expect("Failed to generate proof");

        // Extract the specific Arkworks Bn254 proof from the generic Circom proof
        let proof: ark_groth16::Proof<Bn254> = circom_proof.proof.into();

        prover_log!("Generated Proof!");

        // Construct and return the final ProofPackage
        // threshold_age is not packaged as the Verifier uses their own known threshold
        let proof_package = ProofPackage {
            commitment: credential_package.commitment,
            pk_p: self.pk_p,
            signature: credential_package.signature,
            proof,
        };

        proof_package
    }

    /// Receive status from Verifier
    pub fn receive_access_decision(&mut self, status: AccessStatus) {
        prover_log!("Received Access Decision: {:?}", status);
    }
}
