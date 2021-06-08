use algebra::{Bls12_377, PairingEngine, BW6_761};
use anyhow::Result;
use gumdrop::Options;
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use setup_utils::converters::{batch_exp_mode_from_str, subgroup_check_mode_from_str};
use setup_utils::{
    derive_rng_from_seed, from_slice, upgrade_correctness_check_config, BatchExpMode,
    SubgroupCheckMode, DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
};
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{
        copy_file_if_exists, create_full_parameters, create_parameters_for_chunk,
        download_file_from_azure_async, get_content_length, read_hash_from_file,
        remove_file_if_exists, string_to_phase, Phase, BEACON_HASH_LENGTH,
    },
};
use std::{
    fs::{copy, File},
    io::{Read, Write},
};
use tracing::info;
use tracing_subscriber;

const INITIAL_CHALLENGE_FILENAME: &str = "initial_challenge";
const INITIAL_CHALLENGE_HASH_FILENAME: &str = "initial_challenge.hash";
const COMBINED_NEW_CHALLENGE_FILENAME: &str = "combined_new_challenge";
const COMBINED_NEW_CHALLENGE_HASH_FILENAME: &str = "combined_new_challenge.hash";
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

#[derive(Debug, Options, Clone)]
pub struct VerifyTranscriptOpts {
    help: bool,
    #[options(help = "phase to be run. Must be either phase1 or phase2")]
    pub phase: String,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
    #[options(help = "the beacon hash")]
    pub beacon_hash: String,
    #[options(
        help = "whether to always check whether incoming challenges are in correct subgroup and non-zero",
        default = "false"
    )]
    pub force_correctness_checks: bool,
    #[options(
        help = "which batch exponentiation version to use",
        default = "auto",
        parse(try_from_str = "batch_exp_mode_from_str")
    )]
    pub batch_exp_mode: BatchExpMode,
    #[options(
        help = "which subgroup check version to use",
        default = "auto",
        parse(try_from_str = "subgroup_check_mode_from_str")
    )]
    pub subgroup_check_mode: SubgroupCheckMode,
    #[options(help = "whether to skip ratio check", default = "false")]
    pub skip_ratio_check: bool,
    #[options(help = "curve", default = "bw6")]
    pub curve: String,

    #[options(help = "size of chunks used")]
    pub chunk_size: Option<usize>,
    #[options(help = "number max validators used in the circuit. Only used for phase 2")]
    pub num_validators: Option<usize>,
    #[options(help = "number max epochs used in the circuit. Only used for phase 2")]
    pub num_epochs: Option<usize>,
    #[options(help = "number powers used in phase1. Only used for phase 2")]
    pub phase1_powers: Option<usize>,
    #[options(help = "file with prepared output from phase1. Only used for phase 2")]
    pub phase1_filename: Option<String>,
    #[options(help = "file with prepared circuit. Only used for phase 2")]
    pub circuit_filename: Option<String>,
    #[options(help = "initial query filename. Used only for phase2")]
    pub initial_query_filename: Option<String>,
    #[options(help = "initial full filename. Used only for phase2")]
    pub initial_full_filename: Option<String>,
}

pub struct TranscriptVerifier {
    pub phase: Phase,
    pub transcript: Transcript,
    pub beacon_hash: Vec<u8>,
    pub force_correctness_checks: bool,
    pub batch_exp_mode: BatchExpMode,
    pub subgroup_check_mode: SubgroupCheckMode,
    pub ratio_check: bool,
    pub phase2_options: Option<Phase2Options>,
}

pub struct Phase2Options {
    pub chunk_size: usize,
    pub phase1_powers: usize,
    pub phase1_filename: String,
    pub circuit_filename: String,
    pub initial_query_filename: String,
    pub initial_full_filename: String,
}

impl Phase2Options {
    pub fn new(opts: &VerifyTranscriptOpts) -> Result<Self> {
        Ok(Self {
            chunk_size: opts
                .chunk_size
                .expect("chunk_size must be used when running phase2"),
            phase1_powers: opts
                .phase1_powers
                .expect("phase1_powers must be used when running phase2"),
            phase1_filename: opts
                .phase1_filename
                .as_ref()
                .expect("phase1_filename must be used when running phase2")
                .to_string(),
            circuit_filename: opts
                .circuit_filename
                .as_ref()
                .expect("circuit_filename must be used when running phase2")
                .to_string(),
            initial_query_filename: opts
                .initial_query_filename
                .as_ref()
                .expect("initial_query_filename needed when running phase2")
                .to_string(),
            initial_full_filename: opts
                .initial_full_filename
                .as_ref()
                .expect("initial_full_filename needed when running phase2")
                .to_string(),
        })
    }
}

impl TranscriptVerifier {
    pub fn new(opts: &VerifyTranscriptOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let transcript: Transcript = serde_json::from_str::<Transcript>(&transcript)?;

        let beacon_hash = hex::decode(&opts.beacon_hash)?;
        if beacon_hash.len() != BEACON_HASH_LENGTH {
            return Err(
                VerifyTranscriptError::BeaconHashWrongLengthError(beacon_hash.len()).into(),
            );
        }
        let beacon_value = hex::decode(
            &transcript
                .beacon_hash
                .as_ref()
                .expect("Beacon value should have been something"),
        )?;
        if beacon_hash.clone() != beacon_value {
            return Err(VerifyTranscriptError::BeaconHashWasDifferentError(
                hex::encode(&beacon_value),
                hex::encode(&beacon_hash),
            )
            .into());
        }
        let phase = string_to_phase(&opts.phase)?;
        let phase2_options = match phase {
            Phase::Phase1 => None,
            Phase::Phase2 => Some(Phase2Options::new(&opts)?),
        };
        let verifier = Self {
            phase,
            transcript,
            beacon_hash,
            force_correctness_checks: opts.force_correctness_checks,
            batch_exp_mode: opts.batch_exp_mode,
            subgroup_check_mode: opts.subgroup_check_mode,
            ratio_check: !opts.skip_ratio_check,
            phase2_options,
        };
        Ok(verifier)
    }

    fn run<E: PairingEngine>(&self) -> Result<()> {
        let mut rt = tokio::runtime::Builder::new()
            .threaded_scheduler()
            .enable_all()
            .build()
            .unwrap();

        let ceremony = self
            .transcript
            .rounds
            .last()
            .expect("Should have gotten last round");
        info!("combining");

        remove_file_if_exists(RESPONSE_LIST_FILENAME)?;
        let mut response_list_file = File::create(RESPONSE_LIST_FILENAME)?;

        // Quick check - make sure the all chunks have the same number of contributions.
        // If the coordinator was honest, then each participant would have contributed
        // once to each chunk.
        if !ceremony
            .chunks
            .iter()
            .all(|c| c.contributions.len() == ceremony.chunks[0].contributions.len())
        {
            return Err(
                VerifyTranscriptError::NotAllChunksHaveSameNumberOfContributionsError.into(),
            );
        }

        let current_parameters = Some(ceremony.parameters.clone());

        for (chunk_index, chunk) in ceremony.chunks.iter().enumerate() {
            let contribution = chunk
                .contributions
                .last()
                .expect("Should have gotten contribution");
            // Clean up the previous contribution challenge and response.
            remove_file_if_exists(CHALLENGE_FILENAME)?;
            remove_file_if_exists(CHALLENGE_HASH_FILENAME)?;
            remove_file_if_exists(RESPONSE_FILENAME)?;
            remove_file_if_exists(RESPONSE_HASH_FILENAME)?;
            copy_file_if_exists(NEW_CHALLENGE_FILENAME, CHALLENGE_FILENAME)?;
            remove_file_if_exists(NEW_CHALLENGE_FILENAME)?;
            remove_file_if_exists(NEW_CHALLENGE_HASH_FILENAME)?;

            let contributed_location = contribution.contributed_location()?;
            // Download the response computed by the participant.
            let length = rt.block_on(get_content_length(&contributed_location))?;
            rt.block_on(download_file_from_azure_async(
                &contributed_location,
                length,
                RESPONSE_FILENAME,
            ))?;

            let response_filename = format!("{}_{}", RESPONSE_PREFIX_FOR_AGGREGATION, chunk_index);
            copy(RESPONSE_FILENAME, &response_filename)?;
            response_list_file.write(format!("{}\n", response_filename).as_bytes())?;
            info!("chunk {} verified", chunk.chunk_id);
        }
        drop(response_list_file);

        info!("all rounds and chunks verified, aggregating");
        remove_file_if_exists(COMBINED_FILENAME)?;
        let current_parameters = current_parameters.unwrap();
        let parameters = create_parameters_for_chunk::<E>(&current_parameters, 0)?;
        // Combine the last contributions from each chunk into a single big contributions.
        if self.phase == Phase::Phase1 {
            phase1_cli::combine(RESPONSE_LIST_FILENAME, COMBINED_FILENAME, &parameters);
        } else {
            let phase2_options = self
                .phase2_options
                .as_ref()
                .expect("Phase2 options not used while running phase2 verification");
            phase2_cli::combine(
                phase2_options.initial_query_filename.as_ref(),
                phase2_options.initial_full_filename.as_ref(),
                RESPONSE_LIST_FILENAME,
                COMBINED_FILENAME,
                false,
            );
        }
        info!("combined, applying beacon");
        let parameters = create_full_parameters::<E>(&current_parameters)?;
        remove_file_if_exists(COMBINED_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_NEW_CHALLENGE_FILENAME)?;
        remove_file_if_exists(COMBINED_NEW_CHALLENGE_HASH_FILENAME)?;
        let rng = derive_rng_from_seed(&from_slice(&self.beacon_hash));
        // Apply the random beacon.
        if self.phase == Phase::Phase1 {
            phase1_cli::contribute(
                COMBINED_FILENAME,
                COMBINED_HASH_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                self.batch_exp_mode,
                &parameters,
                rng,
            );
        } else {
            phase2_cli::contribute(
                COMBINED_FILENAME,
                COMBINED_HASH_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                self.batch_exp_mode,
                rng,
            );
        }
        info!("applied beacon, verifying");
        remove_file_if_exists(COMBINED_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME)?;
        // Verify the correctness of the random beacon.
        if self.phase == Phase::Phase1 {
            phase1_cli::transform_pok_and_correctness(
                COMBINED_FILENAME,
                COMBINED_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                self.subgroup_check_mode,
                self.ratio_check,
                &parameters,
            );
        } else {
            phase2_cli::verify(
                COMBINED_FILENAME,
                COMBINED_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                self.subgroup_check_mode,
                false,
            );
        }
        // Verify the consistency of the entire combined contribution, making sure that the
        // correct ratios hold between elements.
        if self.phase == Phase::Phase1 {
            phase1_cli::transform_ratios(
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                &parameters,
            );
        } else {
            phase2_cli::verify(
                INITIAL_CHALLENGE_FILENAME,
                INITIAL_CHALLENGE_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                upgrade_correctness_check_config(
                    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                    self.force_correctness_checks,
                ),
                COMBINED_NEW_CHALLENGE_FILENAME,
                COMBINED_NEW_CHALLENGE_HASH_FILENAME,
                self.subgroup_check_mode,
                true,
            );
        }

        info!("Finished verification successfully!");
        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt().json().init();

    let opts: VerifyTranscriptOpts = VerifyTranscriptOpts::parse_args_default_or_exit();

    let verifier = TranscriptVerifier::new(&opts)
        .expect("Should have been able to create a transcript verifier");
    (match opts.curve.as_str() {
        "bw6" => verifier.run::<BW6_761>(),
        "bls12_377" => verifier.run::<Bls12_377>(),
        _ => Err(VerifyTranscriptError::UnsupportedCurveKindError(opts.curve.clone()).into()),
    })
    .expect("Should have run successfully");
}
