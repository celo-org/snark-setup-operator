use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::error::VerifyTranscriptError;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContributedData {
    pub challenge_hash: String,
    pub response_hash: String,
    pub contribution_duration: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignedContributedData {
    pub data: ContributedData,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedData {
    pub challenge_hash: String,
    pub response_hash: String,
    pub new_challenge_hash: String,
    pub verification_duration: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignedVerifiedData {
    pub data: VerifiedData,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContributionMetadata {
    pub contributed_time: Option<chrono::DateTime<chrono::Utc>>,
    pub contributed_lock_holder_time: Option<chrono::DateTime<chrono::Utc>>,
    pub verified_time: Option<chrono::DateTime<chrono::Utc>>,
    pub verified_lock_holder_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Contribution {
    pub metadata: Option<ContributionMetadata>,

    pub contributor_id: Option<String>,
    pub contributed_location: Option<String>,
    pub contributed_data: Option<SignedContributedData>,
    pub verifier_id: Option<String>,
    pub verified_location: Option<String>,
    pub verified: bool,
    pub verified_data: Option<SignedVerifiedData>,
}

impl Contribution {
    pub fn verified_data(&self) -> Result<&SignedVerifiedData> {
        let verified_data = self
            .verified_data
            .as_ref()
            .ok_or(VerifyTranscriptError::VerifiedDataIsNoneError)?;

        Ok(verified_data)
    }

    pub fn contributed_data(&self) -> Result<&SignedContributedData> {
        let contributed_data = self
            .contributed_data
            .as_ref()
            .ok_or(VerifyTranscriptError::ContributorDataIsNoneError)?;

        Ok(contributed_data)
    }

    pub fn contributor_id(&self) -> Result<&String> {
        let contributor_id = self
            .contributor_id
            .as_ref()
            .ok_or(VerifyTranscriptError::ContributorIDIsNoneError)?;

        Ok(contributor_id)
    }

    pub fn verifier_id(&self) -> Result<&String> {
        let verifier_id = self
            .verifier_id
            .as_ref()
            .ok_or(VerifyTranscriptError::VerifierIDIsNoneError)?;

        Ok(verifier_id)
    }

    pub fn contributed_location(&self) -> Result<&String> {
        let contributed_location = self
            .contributed_location
            .as_ref()
            .ok_or(VerifyTranscriptError::ContributedLocationIsNoneError)?;

        Ok(contributed_location)
    }

    pub fn verified_location(&self) -> Result<&String> {
        let verified_location = self
            .verified_location
            .as_ref()
            .ok_or(VerifyTranscriptError::VerifiedLocationIsNoneError)?;

        Ok(verified_location)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChunkMetadata {
    pub lock_holder_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Chunk {
    pub chunk_id: String,
    pub lock_holder: Option<String>,
    pub contributions: Vec<Contribution>,
    pub metadata: Option<ChunkMetadata>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    pub proving_system: String,
    pub curve_kind: String,
    pub chunk_size: usize,
    pub batch_size: usize,
    pub power: usize,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Ceremony {
    pub version: u64,
    pub contributor_ids: Vec<String>,
    pub verifier_ids: Vec<String>,
    pub chunks: Vec<Chunk>,
    pub parameters: Parameters,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Response<T> {
    pub result: T,
    pub status: String,
}
