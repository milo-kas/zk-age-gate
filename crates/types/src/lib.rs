//! Defines the strict rules (payloads) of the protocol

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use chrono::{Datelike, Months};
use chrono::naive::NaiveDate;
use ed25519_dalek::Signature;

/// Date of Birth
#[derive(Clone, Copy, Debug)]
pub struct DoB {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl DoB { // TODO: input checks
    /// Convert DoB to total days since Epoch (1900 Jan 1)
    ///
    /// Starting at 1900-01-01 guarantees non-negative day counts for living people,
    /// avoiding integer underflow when cast to u32 and fitting within the 32-bit circuit range.
    pub fn to_days_since_epoch(&self) -> u32 {
        let date = NaiveDate::from_ymd_opt(self.year.into(), self.month.into(), self.day.into())
            .expect("Invalid date of birth");

        let epoch = NaiveDate::from_ymd_opt(1900, 1, 1)
            .expect("Valid epoch date");

        let days = (date - epoch).num_days();
        assert!(
            days >= 0,
            "Date of birth must be on or after 1900-01-01 (got {}-{:02}-{:02})",
            self.year, self.month, self.day
        );

        days as u32
    }

    /// Compute the latest permissible DoB for a given age threshold
    pub fn calculate_dob_cutoff(today: NaiveDate, age_years: u8) -> DoB {
        let cutoff = today
            .checked_sub_months(Months::new(age_years as u32 * 12))
            .expect("Valid calendar subtraction");

        Self {
            year: u16::try_from(cutoff.year())
                .expect("Cutoff year out of u16 range"),
            month: cutoff.month() as u8,
            day: cutoff.day() as u8,
        }
    }
}

/// Prover to Issuer payload structure
#[derive(Clone, Debug)]
pub struct AgeRequest {
    // Prover public key (pk_p)
    pub pk_p: Fr,
    // Mock ID, Private input; can be used to generate age
    pub id: String,
}

/// Issuer to Prover payload structure
#[derive(Clone, Debug)]
pub struct CredentialPackage {
    // Private inputs
    pub dob_epoch: u32,
    pub salt: Fr,
    // Public inputs
    pub commitment: Fr,
    pub signature: Signature,
}

/// Credential Package Error
#[derive(Clone, Debug)]
pub enum IssuerError {
    IdNotFound(String),
}

/// Verifier challenge payload
#[derive(Clone, Debug)]
pub struct VerifierChallenge {
    pub nonce: u64,
    pub threshold_epoch: u32,
}

/// Prover to Verifier payload structure
#[derive(Clone, Debug)]
pub struct ProofPackage {
    // All public inputs
    // No threshold DoB epoch as the Verifier already knows it
    pub commitment: Fr,
    pub pk_p: Fr, // Prover public key (pk)
    pub signature: Signature,

    // Proof
    pub proof: Proof<Bn254>,
}

/// Verifier to Prover status update
#[derive(Clone, Debug, PartialEq)]
pub enum AccessStatus {
    Granted,
    Denied,
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
