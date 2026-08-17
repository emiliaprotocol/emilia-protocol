use std::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidFormat(String),
    DepthExceeded(String),
    UnpairedSurrogate(String),
    DuplicateKey(String),
    InvalidSignature(String),
    InvalidQuorum(String),
    InvalidRevocation(String),
    InvalidTimeAttestation(String),
    InvalidTrustReceipt(String),
    InvalidProvenance(String),
    InvalidEvidenceRecord(String),
    NotCanonicalizable(String),
    CurrencyError(String),
    InitiatorError(String),
    ConsumptionError(String),
    WitnessError(String),
    TimestampError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            Error::DepthExceeded(s) => write!(f, "Depth limit exceeded: {}", s),
            Error::UnpairedSurrogate(s) => write!(f, "Unpaired surrogate: {}", s),
            Error::DuplicateKey(s) => write!(f, "Duplicate key: {}", s),
            Error::InvalidSignature(s) => write!(f, "Invalid signature: {}", s),
            Error::InvalidQuorum(s) => write!(f, "Invalid quorum: {}", s),
            Error::InvalidRevocation(s) => write!(f, "Invalid revocation: {}", s),
            Error::InvalidTimeAttestation(s) => write!(f, "Invalid time attestation: {}", s),
            Error::InvalidTrustReceipt(s) => write!(f, "Invalid trust receipt: {}", s),
            Error::InvalidProvenance(s) => write!(f, "Invalid provenance chain: {}", s),
            Error::InvalidEvidenceRecord(s) => write!(f, "Invalid evidence record: {}", s),
            Error::NotCanonicalizable(s) => write!(f, "Not canonicalizable: {}", s),
            Error::CurrencyError(s) => write!(f, "Currency error: {}", s),
            Error::InitiatorError(s) => write!(f, "Initiator error: {}", s),
            Error::ConsumptionError(s) => write!(f, "Consumption error: {}", s),
            Error::WitnessError(s) => write!(f, "Witness error: {}", s),
            Error::TimestampError(s) => write!(f, "Timestamp error: {}", s),
        }
    }
}

impl std::error::Error for Error {}
