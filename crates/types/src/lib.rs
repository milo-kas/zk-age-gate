//! Defines the strict rules (payloads) of the protocol

use ark_bn254::Fr;
use ed25519_dalek::Signature;

// Prover to Issuer payload structure
#[derive(Clone, Debug)]
pub struct AgeRequest {
    // Prover public key
    pub pk_p: Fr,
    // Mock ID
    pub id: String,
}

// Issuer to Prover payload structure
#[derive(Clone, Debug)]
pub struct SignedCommitment {
    pub age: u8,
    pub salt: Fr,
    pub commitment: Fr,
    pub signature: Signature,
}

// Prover to Verifier payload structure
#[derive(Clone, Debug)]
pub struct ProofPackage {
    // Public inputs:
    // No threshold age as the Verifier already knows it
    pub commitment: Fr,
    pub prover_pk_p: Fr,
    pub signature: Signature,
    // Proof
    pub proof: Vec<u8>,
}
