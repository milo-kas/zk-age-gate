//! Defines the strict rules (payloads) of the protocol

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use ed25519_dalek::Signature;

/// Prover to Issuer payload structure
#[derive(Clone, Debug)]
pub struct AgeRequest {
    // Prover public key
    pub pk_p: Fr,
    // Mock ID, Private input; can be used to generate age
    pub id: String,
}

/// Issuer to Prover payload structure
#[derive(Clone, Debug)]
pub struct CredentialPackage {
    // Private inputs
    pub age: u8,
    pub salt: Fr,
    // Public inputs
    pub commitment: Fr,
    pub signature: Signature,
}

/// Prover to Verifier payload structure
#[derive(Clone, Debug)]
pub struct ProofPackage {
    // All public inputs
    // No threshold age as the Verifier already knows it
    pub commitment: Fr,
    pub pk_p: Fr,
    pub signature: Signature,

    // Proof
    pub proof: Proof<Bn254>,
}


// Log format with colours for each Actor
pub use colored;

/// Global Protocol Coordinator
#[macro_export]
macro_rules! coord_log {
    ($($arg:tt)*) => {
        println!("{}", format!("[Protocol Coordinator] {}", format_args!($($arg)*)).white().bold());
    };
}

/// Global Issuer
#[macro_export]
macro_rules! issuer_log {
    ($($arg:tt)*) => {
        println!("{}", format!("[Issuer (INTERNAL)] {}", format_args!($($arg)*)).magenta());
    };
}

/// Global Prover
#[macro_export]
macro_rules! prover_log {
    ($($arg:tt)*) => {
        println!("{}", format!("[Prover (INTERNAL)] {}", format_args!($($arg)*)).blue());
    };
}

/// Global Verifier
#[macro_export]
macro_rules! verifier_log {
    ($($arg:tt)*) => {
        println!("{}", format!("[Verifier (INTERNAL)] {}", format_args!($($arg)*)).yellow());
    };
}