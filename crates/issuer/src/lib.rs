//! Defines the Issuer Actor

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::{RngCore, rngs::OsRng};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::collections::HashMap;
use types::{
    AgeRequest, CredentialPackage, DoB, IssuerError, colored::Colorize, issuer_log, schema,
};

/// Issuer acts as a trusted authority (i.e. KYC provider, government, etc)
pub struct Issuer {
    /// Secret key used to sign age commitment
    signing_key: SigningKey,
    identity_records: HashMap<String, DoB>,
}

impl Issuer {
    /// Initialise the Issuer with a newly generated Ed25519 keypair
    pub fn new(identity_records: HashMap<String, DoB>) -> Self {
        issuer_log!("Initialising...");

        let mut rng = OsRng;

        // Generate 32 bytes of OS entropy
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Generate keypair (secret signing key and public verifying key)
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            signing_key,
            identity_records,
        }
    }

    /// Public key getter, allows Verifier to validate signature in the ProofPackage
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Process Prover's ID and issue the Credential Package incl. the Signed Commitment
    pub fn issue_credential(&self, request: AgeRequest) -> Result<CredentialPackage, IssuerError> {
        let mut rng = OsRng;

        // Fetch the age associated with ID
        issuer_log!("Verifying ID: {}...", request.id);
        let dob = match self.identity_records.get(&request.id) {
            Some(dob) => *dob,
            None => return Err(IssuerError::IdNotFound(request.id)),
        };

        // Convert DoB to protocol Epoch
        let dob_epoch = dob.to_days_since_epoch();

        // Generate secure random salt and wrap to BN254 field format
        let salt = Fr::rand(&mut rng);
        let dob_epoch_fr = Fr::from(dob_epoch);

        // Create hasher
        let mut hasher = Poseidon::<Fr>::new_circom(3).expect("Failed to initialise Poseidon");

        // Hash: Commitment = Poseidon(age, salt, pk_p),
        // Binding the prover's age, random salt, and prover's public key (pk_p) together
        let commitment = hasher
            .hash(&[dob_epoch_fr, salt, request.pk_p])
            .expect("Poseidon hash failed");

        // Sign the commitment
        // Convert the BN254 commitment to little-endian byte arr AND schema version, to sign
        let signature_payload_bytes = schema::bind_commitment_with_version(&commitment);
        let signature: Signature = self.signing_key.sign(&signature_payload_bytes);

        issuer_log!("Packaging credentials...");

        // Package the credentials.
        Ok(CredentialPackage {
            schema_version: schema::VERSION,
            dob_epoch,
            salt,
            commitment,
            signature,
        })
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}
