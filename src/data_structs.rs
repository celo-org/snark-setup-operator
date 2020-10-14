use serde::{Deserialize, Serialize};

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
