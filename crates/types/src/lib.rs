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
