use crate::data_structs::Parameters;
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
    #[error("Not all chunks have the same number of contributions")]
    NotAllChunksHaveSameNumberOfContributionsError,
    #[error("Beacon hash had wrong length: {0}")]
    BeaconHashWrongLengthError(usize),
    #[error("Beacon hash was different: expected {0}, got {1}")]
    BeaconHashWasDifferentError(String, String),
    #[error("Parameters were different between rounds: expected {0:?}, got {1:?}")]
    ParametersDifferentBetweenRounds(Parameters, Parameters),
    #[error("Round index was wrong: expected {0}, got {1}")]
    RoundWrongIndexError(u64, u64),
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

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("Participant already exists: {0}, existing participants are {1:?}")]
    ParticipantAlreadyExistsError(String, Vec<String>),
    #[error("Participant does not exist: {0}, existing participants are {1:?}")]
    ParticipantDoesNotExistError(String, Vec<String>),
    #[error("Participant unexpected on chunk {0}: expected {1}, got {2}")]
    ParticipantUnexpected(usize, String, String),
}

#[derive(Debug, Error)]
pub enum ContributeError {
    #[error("Could not choose random chunk")]
    CouldNotChooseChunkError,
    #[error("Could not find chunk with ID: {0}")]
    CouldNotFindChunkWithIDError(String),
    #[error("Contributions list was empty for chunk with ID: {0}")]
    ContributionListWasEmptyForChunkID(String),
    #[error("Verified location was none for the last contribution in chunk with ID: {0}")]
    VerifiedLocationWasNoneForChunkID(String),
    #[error("Contributed location was none for the last contribution in chunk with ID: {0}")]
    ContributedLocationWasNoneForChunkID(String),
    #[error("Unsupported decryptor")]
    UnsupportedDecryptorError,
    #[error("Could not read passphrase")]
    CouldNotReadPassphraseError,
    #[error("Failed running contribute: {0}")]
    FailedRunningContributeError(String),
    #[error("Failed running verification: {0}")]
    FailedRunningVerificationError(String),
    #[error("Seed was none")]
    SeedWasNoneError,
    #[error("Lane was null: {0}")]
    LaneWasNullError(String),
    #[error("Lane {0} did not contain chunk with ID: {1}")]
    LaneDidNotContainChunkWithIDError(String, String),
    #[error("Lane {0} already contains chunk with ID: {1}")]
    LaneAlreadyContainsChunkWithIDError(String, String),
    #[error("Could not find chunk with ID {0} in any lane")]
    CouldNotFindChunkWithIDInAnyLaneError(String),
    #[error("Could not find chunk with ID {0} in the ceremony locked by participant {1}")]
    CouldNotFindChunkWithIDLockedByParticipantError(String, String),
    #[error("Got exit signal")]
    GotExitSignalError,
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("Could not upload to azure, status was: {0}")]
    CouldNotUploadToAzureError(String),
    #[error("Could not parse SAS: {0}")]
    CouldNotParseSAS(String),
}

#[derive(Debug, Error)]
pub enum UtilsError {
    #[error("Unknown upload mode: {0}")]
    UnknownUploadModeError(String),
    #[error("Option was none")]
    MissingOptionErr,
    #[error("Unknown participation mode: {0}")]
    UnknownParticipationModeError(String),
    #[error("Unknown phase: {0}")]
    UnknownPhaseError(String),
    #[error("Phase not selected")]
    NoPhaseError,
    #[error("Retry failed: {0}")]
    RetryFailedError(String),
    #[error("Could not read passphrase")]
    CouldNotReadPassphraseError,
    #[error("Could not read entropy")]
    CouldNotReadEntropyError,
    #[error("Entropy was none")]
    EntropyWasNoneError,
    #[error("Unsupported decryptor")]
    UnsupportedDecryptorError,
    #[error("Attestation too short, got length {0}")]
    AttestationTooShort(usize),
}

#[derive(Debug, Error)]
pub enum NewRoundError {
    #[error("Versions were the same: {0}")]
    RoundSameError(u64),
    #[error("Expected participants were different: current {0:?}, expected {1:?}")]
    DifferentExpectedParticipantsError(HashSet<String>, HashSet<String>),
    #[error("Transcript cannot be verified independently in phase 2")]
    NoVerificationPhase2,
}
