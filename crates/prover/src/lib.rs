//! Defines the Prover Actor

use types::{AgeRequest, CredentialPackage, ProofPackage};

use ark_bn254::Fr;
use getrandom::{SysRng, rand_core::{UnwrapErr, Rng}};

// TODO: verifier sends age threshold request

/// Prover acts as the end-user proving their age is above a given threshold
pub struct Prover {
    // Private storage (prover key and credential package)
    pk_p: Fr,
    credential_package: Option<CredentialPackage>
}

impl Prover {
    /// Instantiate a new Prover
    pub fn new() -> Self {
        println!("[Prover (INTERNAL)] Initalising...");

        let mut csprng = UnwrapErr(SysRng);
        Self {
            pk_p: Fr::from(csprng.next_u64()),
            credential_package: None
        }
    }

    /// Package the Age Request for the Issuer
    pub fn create_age_request(&self, id: &str) -> AgeRequest {
        println!("[Prover (INTERNAL)] Packaging AgeRequest...");

        let age_request = AgeRequest {
            pk_p: self.pk_p,
            id: id.to_string()
        };

        age_request
    }

    /// Take the Credential Package issued from the Issuer
    pub fn receive_credential_package(&mut self, package: CredentialPackage) {
        println!("[Prover (INTERNALLY)] Credential Package received!");
        println!("[Prover (INTERNALLY)] Storing Credential Package ...");
        self.credential_package = Some(package);

        println!("[Prover (INTERNAL):");
        println!("{:#?}", self.credential_package);
    }

    // TODO: generate proof

}
