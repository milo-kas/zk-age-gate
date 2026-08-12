//! Defines the Issuer Actor

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::{
    SysRng,
    rand_core::{Rng, UnwrapErr},
};
use light_poseidon::{Poseidon, PoseidonHasher};

use types::{colored::Colorize, issuer_log, AgeRequest, CredentialPackage};

/// Issuer acts as a trusted authority (i.e. KYC provider, government, etc)
pub struct Issuer {
    /// Private key used to sign age commitment
    signing_key: SigningKey,
}

impl Issuer {
    /// Initialise the Issuer with a newly generated Ed25519 keypair
    pub fn new() -> Self {
        issuer_log!("Initalising...");

        // Guarantee that the provided entropy is from the OS and not a fallback
        let mut csprng = UnwrapErr(SysRng);
        // Generate keypair
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Public key getter, allows Verifier to validate signature in the ProofPackage
    pub fn get_public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Process Prover's ID and issue the Credential Package incl. the Signed Commitment
    pub fn issue_credential(&self, request: AgeRequest) -> CredentialPackage {
        let mut csprng = UnwrapErr(SysRng);

        // Simulate reading the ID to determine age -- PoC only
        issuer_log!("Verifying ID: {}...", request.id);
        let age: u8 = 20; // dummy age TODO: make it random as per demo using the ID as entropy

        // Generate secure random salt and wrap to BN254 field format
        let salt = Fr::from(csprng.next_u64());
        let age_fr = Fr::from(age);

        // Create hasher
        let mut hasher = Poseidon::<Fr>::new_circom(3).expect("Failed to initialise Poseidon");

        // Hash: Commitment = Poseidon(age, salt, pk_P),
        // Binding the prover's age, random salt, and prover's public key together
        let commitment = hasher
            .hash(&[age_fr, salt, request.pk_p])
            .expect("Poseidon hash failed");

        // Sign the commitment
        // Convert the BN254 commitment to little-endian byte arr, to sign
        let commitment_bytes = commitment.into_bigint().to_bytes_le();
        let signature: Signature = self.signing_key.sign(&commitment_bytes);

        issuer_log!("Packaging credentials...");

        // Package the credentials.
        CredentialPackage {
            age,
            salt,
            commitment,
            signature,
        }
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}
