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
}

const ADDRESS_LENGTH: usize = 20;
const CHALLENGE_FILENAME: &str = "challenge";
const CHALLENGE_HASH_FILENAME: &str = "challenge.hash";
const RESPONSE_FILENAME: &str = "response";
const RESPONSE_HASH_FILENAME: &str = "response.hash";
const NEW_CHALLENGE_FILENAME: &str = "new_challenge";
const NEW_CHALLENGE_HASH_FILENAME: &str = "new_challenge.hash";
const RESPONSE_PREFIX_FOR_AGGREGATION: &str = "response";
const RESPONSE_LIST_FILENAME: &str = "response_list";
const COMBINED_FILENAME: &str = "combined";
const COMBINED_HASH_FILENAME: &str = "combined.hash";
const COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME: &str =
    "combined_verified_pok_and_correctness";
const COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME: &str =
    "combined_verified_pok_and_correctness.hash";
const COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME: &str =
    "combined_new_verified_pok_and_correctness_new_challenge";
const COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME: &str =
    "combined_verified_pok_and_correctness_new_challenge.hash";

use snark_setup_operator::data_structs::{
    Ceremony, Chunk, Contribution, Response, SignedContributedData, SignedVerifiedData,
    VerifiedData,
};

use anyhow::Result;
use ethers::types::{Address, Signature};
use gumdrop::Options;
use phase1::{ContributionMode, CurveParameters, Phase1Parameters, ProvingSystem};
use phase1_cli::{
    combine, contribute, new_challenge, transform_pok_and_correctness, transform_ratios,
};
use serde::Serialize;
use setup_utils::{beacon_randomness, derive_rng_from_seed, from_slice};
use std::{
    collections::HashSet,
    fs::{copy, remove_file, File},
    io::{self, Read, Write},
    marker::PhantomData,
    path::Path,
    str::FromStr,
};
use thiserror::Error;
use tracing::info;
use zexe_algebra::{Bls12_377, PairingEngine, BW6_761};

#[derive(Debug, Options, Clone)]
pub struct VerifyTranscriptOpts {
    #[options(
        help = "the path of the transcript json file",
        default = "transcript.json"
    )]
    pub transcript_path: String,
    #[options(help = "participant addresses to be verified", required)]
    pub participant_id: Vec<String>,
}

fn remove_file_if_exists(file_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        remove_file(file_path)?;
    }
    Ok(())
}

fn copy_file_if_exists(file_path: &str, dest_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        copy(file_path, dest_path)?;
    }
    Ok(())
}

fn download_file(url: &str, file_path: &str) -> Result<()> {
    remove_file_if_exists(file_path)?;
    let mut resp = reqwest::blocking::get(url)?;
    let mut out = File::create(file_path)?;
    resp.copy_to(&mut out)?;
    Ok(())
}

fn vrs_to_rsv(rsv: &str) -> String {
    format!("{}{}{}", &rsv[2..66], &rsv[66..130], &rsv[..2])
}

fn verify_signed_data<T: Serialize>(data: &T, signature: &str, id: &str) -> Result<()> {
    let vrs_signature = &signature[2..];
    let rsv_signature = vrs_to_rsv(vrs_signature);
    let signature = Signature::from_str(&rsv_signature)?;
    let serialized_data = serde_json::to_string(data)?;

    let deserialized_id = hex::decode(&id[2..])?;
    if deserialized_id.len() != ADDRESS_LENGTH {
        return Err(VerifyTranscriptError::IDWrongLength(deserialized_id.len()).into());
    }
    let mut address = [0u8; ADDRESS_LENGTH];
    address.copy_from_slice(&deserialized_id);
    let address = Address::from(address);
    signature.verify(serialized_data, address)?;

    Ok(())
}

fn read_hash_from_file(file_name: &str) -> Result<String> {
    let mut hash = vec![];
    File::open(file_name)
        .expect("Should have opened hash file.")
        .read_to_end(&mut hash)
        .expect("Should have read hash file.");
    let hash_hex = hex::encode(&hash);
    Ok(hash_hex)
}

fn verified_data_from_contribution(contribution: &Contribution) -> Result<&SignedVerifiedData> {
    let verified_data = contribution
        .verified_data
        .as_ref()
        .ok_or(VerifyTranscriptError::VerifiedDataIsNoneError)?;

    Ok(verified_data)
}

fn contributed_data_from_contribution(
    contribution: &Contribution,
) -> Result<&SignedContributedData> {
    let contributed_data = contribution
        .contributed_data
        .as_ref()
        .ok_or(VerifyTranscriptError::ContributorDataIsNoneError)?;

    Ok(contributed_data)
}

fn contributor_id_from_contribution(contribution: &Contribution) -> Result<&String> {
    let contributor_id = contribution
        .contributor_id
        .as_ref()
        .ok_or(VerifyTranscriptError::ContributorIDIsNoneError)?;

    Ok(contributor_id)
}

fn verifier_id_from_contribution(contribution: &Contribution) -> Result<&String> {
    let verifier_id = contribution
        .verifier_id
        .as_ref()
        .ok_or(VerifyTranscriptError::VerifierIDIsNoneError)?;

    Ok(verifier_id)
}

fn contributed_location_from_contribution(contribution: &Contribution) -> Result<&String> {
    let contributed_location = contribution
        .contributed_location
        .as_ref()
        .ok_or(VerifyTranscriptError::ContributedLocationIsNoneError)?;

    Ok(contributed_location)
}

fn verified_location_from_contribution(contribution: &Contribution) -> Result<&String> {
    let verified_location = contribution
        .verified_location
        .as_ref()
        .ok_or(VerifyTranscriptError::VerifiedLocationIsNoneError)?;

    Ok(verified_location)
}

fn check_challenge_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(VerifyTranscriptError::WrongChallengeHash(a.to_string(), b.to_string()).into());
    }

    Ok(())
}

fn check_response_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(VerifyTranscriptError::WrongResponseHash(a.to_string(), b.to_string()).into());
    }

    Ok(())
}

fn check_new_challenge_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(
            VerifyTranscriptError::WrongNewChallengeHash(a.to_string(), b.to_string()).into(),
        );
    }

    Ok(())
}

fn proving_system_from_str(proving_system_str: &str) -> Result<ProvingSystem> {
    let proving_system = match proving_system_str {
        "groth16" => ProvingSystem::Groth16,
        "marlin" => ProvingSystem::Marlin,
        _ => {
            return Err(VerifyTranscriptError::UnsupportedProvingSystemError(
                proving_system_str.to_string(),
            )
            .into());
        }
    };
    Ok(proving_system)
}

pub struct TranscriptVerifier {
    pub ceremony: Ceremony,
    pub participant_ids: Vec<String>,
}

impl TranscriptVerifier {
    pub fn new(opts: &VerifyTranscriptOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&transcript)?.result;
        let verifier = Self {
            ceremony,
            participant_ids: opts.participant_id.clone(),
        };
        Ok(verifier)
    }

    fn create_parameters_for_chunk<E: PairingEngine>(
        &self,
        chunk_index: usize,
    ) -> Result<Phase1Parameters<E>> {
        let proving_system =
            proving_system_from_str(self.ceremony.parameters.proving_system.as_str())?;
        let parameters = Phase1Parameters::<E>::new_chunk(
            ContributionMode::Chunked,
            chunk_index,
            self.ceremony.parameters.chunk_size,
            proving_system,
            self.ceremony.parameters.power,
            self.ceremony.parameters.batch_size,
        );
        Ok(parameters)
    }

    fn create_full_parameters<E: PairingEngine>(&self) -> Result<Phase1Parameters<E>> {
        let proving_system =
            proving_system_from_str(self.ceremony.parameters.proving_system.as_str())?;
        let parameters = Phase1Parameters::<E>::new_full(
            proving_system,
            self.ceremony.parameters.power,
            self.ceremony.parameters.batch_size,
        );
        Ok(parameters)
    }

    fn run<E: PairingEngine>(&self) -> Result<()> {
        let participant_ids: HashSet<_> = self.participant_ids.iter().cloned().collect();
        remove_file_if_exists(RESPONSE_LIST_FILENAME)?;
        let mut response_list_file = File::create(RESPONSE_LIST_FILENAME)?;

        for (chunk_index, chunk) in self.ceremony.chunks.iter().enumerate() {
            let parameters = self.create_parameters_for_chunk::<E>(chunk_index)?;
            let mut current_new_challenge_hash = String::new();
            for (i, contribution) in chunk.contributions.iter().enumerate() {
                remove_file_if_exists(CHALLENGE_FILENAME)?;
                remove_file_if_exists(CHALLENGE_HASH_FILENAME)?;
                copy_file_if_exists(NEW_CHALLENGE_FILENAME, CHALLENGE_FILENAME)?;
                remove_file_if_exists(RESPONSE_FILENAME)?;
                remove_file_if_exists(RESPONSE_HASH_FILENAME)?;
                remove_file_if_exists(NEW_CHALLENGE_FILENAME)?;
                remove_file_if_exists(NEW_CHALLENGE_HASH_FILENAME)?;
                if i == 0 {
                    let verified_data = verified_data_from_contribution(contribution)?;
                    new_challenge(
                        NEW_CHALLENGE_FILENAME,
                        NEW_CHALLENGE_HASH_FILENAME,
                        &parameters,
                    );
                    let new_challenge_hash_from_file =
                        read_hash_from_file(NEW_CHALLENGE_HASH_FILENAME)?;
                    check_new_challenge_hashes_same(
                        &verified_data.data.new_challenge_hash,
                        &new_challenge_hash_from_file,
                    )?;
                    current_new_challenge_hash = verified_data.data.new_challenge_hash.clone();
                    continue;
                }
                let contributed_data = contributed_data_from_contribution(contribution)?;
                let contributor_id = contributor_id_from_contribution(contribution)?;
                verify_signed_data(
                    &contributed_data.data,
                    &contributed_data.signature,
                    &contributor_id,
                )?;

                check_new_challenge_hashes_same(
                    &contributed_data.data.challenge_hash,
                    &current_new_challenge_hash,
                )?;

                let verified_data = verified_data_from_contribution(contribution)?;
                let verifier_id = verifier_id_from_contribution(contribution)?;
                verify_signed_data(&verified_data.data, &verified_data.signature, &verifier_id)?;

                check_challenge_hashes_same(
                    &contributed_data.data.challenge_hash,
                    &verified_data.data.challenge_hash,
                )?;
                check_response_hashes_same(
                    &contributed_data.data.response_hash,
                    &verified_data.data.response_hash,
                )?;

                let contributed_location = contributed_location_from_contribution(contribution)?;
                download_file(contributed_location, RESPONSE_FILENAME)?;

                transform_pok_and_correctness(
                    CHALLENGE_FILENAME,
                    CHALLENGE_HASH_FILENAME,
                    RESPONSE_FILENAME,
                    RESPONSE_HASH_FILENAME,
                    NEW_CHALLENGE_FILENAME,
                    NEW_CHALLENGE_HASH_FILENAME,
                    &parameters,
                );

                let challenge_hash_from_file = read_hash_from_file(CHALLENGE_HASH_FILENAME)?;
                check_challenge_hashes_same(
                    &verified_data.data.challenge_hash,
                    &challenge_hash_from_file,
                )?;
                check_challenge_hashes_same(
                    &verified_data.data.challenge_hash,
                    &current_new_challenge_hash,
                )?;

                let response_hash_from_file = read_hash_from_file(RESPONSE_HASH_FILENAME)?;
                check_response_hashes_same(
                    &verified_data.data.response_hash,
                    &response_hash_from_file,
                )?;

                let new_challenge_hash_from_file =
                    read_hash_from_file(NEW_CHALLENGE_HASH_FILENAME)?;
                check_new_challenge_hashes_same(
                    &verified_data.data.new_challenge_hash,
                    &new_challenge_hash_from_file,
                )?;

                current_new_challenge_hash = verified_data.data.new_challenge_hash.clone();

                if i == chunk.contributions.len() - 1 {
                    let response_filename =
                        format!("{}_{}\n", RESPONSE_PREFIX_FOR_AGGREGATION, chunk_index);
                    copy(RESPONSE_FILENAME, &response_filename)?;
                    response_list_file.write(response_filename.as_bytes())?;
                }
            }
            info!("chunk {} verified", chunk.chunk_id);
        }
        drop(response_list_file);
        info!("all chunks verified, aggregating");
        remove_file_if_exists(COMBINED_FILENAME)?;
        let parameters = self.create_parameters_for_chunk::<E>(0)?;
        combine(RESPONSE_LIST_FILENAME, COMBINED_FILENAME, &parameters);
        info!("combined, applying beacon");
        let parameters = self.create_full_parameters::<E>()?;
        remove_file_if_exists(COMBINED_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
        let beacon_hash =
            hex::decode("0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620")
                .expect("could not hex decode beacon hash");
        let rng = derive_rng_from_seed(&beacon_randomness(from_slice(&beacon_hash)));
        contribute(
            COMBINED_FILENAME,
            COMBINED_HASH_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
            &parameters,
            rng,
        );
        info!("applied beacon, verifying");
        remove_file_if_exists(COMBINED_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME)?;
        transform_pok_and_correctness(
            COMBINED_FILENAME,
            COMBINED_HASH_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
            &parameters,
        );
        transform_ratios(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
            &parameters,
        );

        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    let opts: VerifyTranscriptOpts = VerifyTranscriptOpts::parse_args_default_or_exit();

    let verifier = TranscriptVerifier::new(&opts)
        .expect("Should have been able to create a transcript verifier.");
    (match verifier.ceremony.parameters.curve_kind.as_str() {
        "bw6" => verifier.run::<BW6_761>(),
        "bls12_377" => verifier.run::<Bls12_377>(),
        _ => Err(VerifyTranscriptError::UnsupportedCurveKindError(
            verifier.ceremony.parameters.curve_kind.clone(),
        )
        .into()),
    })
    .expect("Should have run successfully");
}
