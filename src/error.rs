use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyTranscriptError {
    #[error("Contributor data was none")]
    ContributorDataIsNoneError,
    #[error("Verified data was none")]
    VerifiedDataIsNoneError,
    #[error("Contributor ID was none")]
    ContributorIDIsNoneError,
    #[error("Contributor ID was of wrong length: {0}")]
    IDWrongLength(usize),
    #[error("Verifier ID was none")]
    VerifierIDIsNoneError,
    #[error("Wrong new challenge hash: expected {0}, got {1}")]
    WrongNewChallengeHash(String, String),
    #[error("Wrong challenge hash: expected {0}, got {1}")]
    WrongChallengeHash(String, String),
    #[error("Wrong response hash: expected {0}, got {1}")]
    WrongResponseHash(String, String),
    #[error("Contributed location was none")]
    ContributedLocationIsNoneError,
    #[error("Verified location was none")]
    VerifiedLocationIsNoneError,
    #[error("Unsupported curve kind: {0}")]
    UnsupportedCurveKindError(String),
    #[error("Unsupported proving system: {0}")]
    UnsupportedProvingSystemError(String),
    #[error("Not all participant IDs present, required: {0:?} got: {1:?}")]
    NotAllParticipantsPresent(HashSet<String>, HashSet<String>),
}

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("Metadata was none")]
    MetadataNoneError,
    #[error("Lock time was none")]
    LockTimeIsNoneError,
    #[error("Lock holder was none")]
    LockHolderIsNoneError,
}
