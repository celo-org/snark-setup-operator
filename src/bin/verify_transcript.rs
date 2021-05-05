use anyhow::Result;
use gumdrop::Options;
use setup_utils::converters::{batch_exp_mode_from_str, subgroup_check_mode_from_str};
use phase1_cli::*;
use phase2_cli::*;
use setup_utils::{
    derive_rng_from_seed, from_slice, upgrade_correctness_check_config, BatchExpMode,
    SubgroupCheckMode, DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
    DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
};
use snark_setup_operator::data_structs::Ceremony;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{
        check_challenge_hashes_same, check_new_challenge_hashes_same, check_response_hashes_same,
        copy_file_if_exists, create_full_parameters, create_parameters_for_chunk,
        download_file_from_azure_async, read_hash_from_file, remove_file_if_exists, response_size,
        verify_signed_data, BEACON_HASH_LENGTH,
        Phase, string_to_phase,
    },
};
use std::{
    collections::HashSet,
    fs::{copy, File},
    io::{Read, Write},
};
use tracing::info;
use algebra::{Bls12_377, PairingEngine, BW6_761};

const CHALLENGE_FILENAME: &str = "challenge";
const CHALLENGE_HASH_FILENAME: &str = "challenge.hash";
const RESPONSE_FILENAME: &str = "response";
const RESPONSE_HASH_FILENAME: &str = "response.hash";
const NEW_CHALLENGE_FILENAME: &str = "new_challenge";
const NEW_CHALLENGE_HASH_FILENAME: &str = "new_challenge.hash";
const RESPONSE_PREFIX_FOR_AGGREGATION: &str = "response";
const RESPONSE_LIST_FILENAME: &str = "response_list";
const NEW_CHALLNGE_PREFIX_FOR_NEXT_ROUND: &str = "new_challenge";
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
    #[options(
        help = "phase to be run. Must be either phase1 or phase2",
    )]
    pub phase: String,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
    #[options(help = "apply beacon")]
    pub apply_beacon: bool,
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
    #[options(
        help = "initial query filename. Used only for phase2",
    )]
    pub initial_query_filename: Option<String>,
    #[options(
        help = "initial full filename. Used only for phase2",
    )]
    pub initial_full_filename: Option<String>,    
}

pub struct TranscriptVerifier {
    pub phase: Phase,
    pub transcript: Transcript,
    pub apply_beacon: bool,
    pub beacon_hash: Vec<u8>,
    pub force_correctness_checks: bool,
    pub batch_exp_mode: BatchExpMode,
    pub subgroup_check_mode: SubgroupCheckMode,
    pub ratio_check: bool,
    pub phase2_options: Option<Phase2Options>
}

pub struct Phase2Options {
    pub chunk_size: usize, 
    pub num_validators: usize,
    pub num_epochs: usize,
    pub phase1_powers: usize,
    pub phase1_filename: String,
    pub initial_query_filename: String,
    pub initial_full_filename: String,
}

impl Phase2Options {
    pub fn new(opts: &VerifyTranscriptOpts) -> Result<Self> {
        Ok(Self {
            chunk_size: opts.chunk_size.expect("chunk_size must be used when running phase2"),
            num_validators: opts.num_validators.expect("num_validators must be used when running phase2"),
            num_epochs: opts.num_epochs.expect("num_epochs must be used when running phase2"),
            phase1_powers: opts.phase1_powers.expect("phase1_powers must be used when running phase2"),
            phase1_filename: opts.phase1_filename.as_ref().expect("phase1_filename must be used when running phase2").to_string(),
            initial_query_filename: opts.initial_query_filename.as_ref().expect("initial_query_filename needed when running phase2").to_string(), 
            initial_full_filename: opts.initial_full_filename.as_ref().expect("initial_full_filename needed when running phase2").to_string(), 
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
            apply_beacon: opts.apply_beacon,
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

        let mut current_parameters = None;
        let mut previous_round: Option<Ceremony> = None;
        for (round_index, ceremony) in self.transcript.rounds.iter().enumerate() {
            let round_index = round_index as u64;
            info!("verifying round {}", round_index);

            // These are the participant IDs we discover in the transcript.
            let mut participant_ids_from_poks = HashSet::new();

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

            match current_parameters.as_ref() {
                None => {
                    current_parameters = Some(ceremony.parameters.clone());
                }
                Some(existing_parameters) => {
                    if existing_parameters != &ceremony.parameters {
                        return Err(VerifyTranscriptError::ParametersDifferentBetweenRounds(
                            existing_parameters.clone(),
                            ceremony.parameters.clone(),
                        )
                        .into());
                    }
                }
            }

            if round_index != ceremony.round {
                return Err(VerifyTranscriptError::RoundWrongIndexError(
                    round_index,
                    ceremony.round,
                )
                .into());
            }

            if self.phase == Phase::Phase2 {
                let phase2_options = self.phase2_options.as_ref().expect("Phase2 options not used while running phase2 verification"); 
                phase2_cli::new_challenge(
                    NEW_CHALLENGE_FILENAME,
                    NEW_CHALLENGE_HASH_FILENAME,
                    phase2_options.chunk_size,
                    &phase2_options.phase1_filename,
                    phase2_options.phase1_powers,
                    phase2_options.num_validators,
                    phase2_options.num_epochs,
                );
            }

            for (chunk_index, chunk) in ceremony.chunks.iter().enumerate() {
                let parameters =
                    create_parameters_for_chunk::<E>(&ceremony.parameters, chunk_index)?;
                let mut current_new_challenge_hash = String::new();
                for (i, contribution) in chunk.contributions.iter().enumerate() {
                    // Clean up the previous contribution challenge and response.
                    if self.phase == Phase::Phase1 {
                        remove_file_if_exists(CHALLENGE_FILENAME)?;
                        remove_file_if_exists(CHALLENGE_HASH_FILENAME)?;
                        remove_file_if_exists(RESPONSE_FILENAME)?;
                        remove_file_if_exists(RESPONSE_HASH_FILENAME)?;
                        copy_file_if_exists(NEW_CHALLENGE_FILENAME, CHALLENGE_FILENAME)?;
                        remove_file_if_exists(NEW_CHALLENGE_FILENAME)?;
                        remove_file_if_exists(NEW_CHALLENGE_HASH_FILENAME)?;
                    } else {
                        copy_file_if_exists(NEW_CHALLENGE_FILENAME, CHALLENGE_FILENAME)?;
                        let challenge_filename = format!("{}.{}", NEW_CHALLENGE_FILENAME, chunk_index);
                        copy_file_if_exists(&format!("{}.{}", NEW_CHALLENGE_FILENAME, chunk_index), NEW_CHALLENGE_FILENAME)?;
                        let challenge_contents = std::fs::read(challenge_filename).expect("should have read challenge");
                        let hash = setup_utils::calculate_hash(&challenge_contents);
                        std::fs::File::create(format!("{}.hash", NEW_CHALLENGE_FILENAME))
                            .expect("unable to open new challenge hash file")
                            .write_all(hash.as_slice())
                            .expect("unable to write new challenge hash");
                    }

                    if i == 0 {
                        if round_index == 0 {
                            // This is the initialization pseudo-contribution, so we verify it was
                            // deterministically created by `new`.
                            let verified_data = contribution.verified_data()?;
                            if self.phase == Phase::Phase1 {
                                phase1_cli::new_challenge(
                                    NEW_CHALLENGE_FILENAME,
                                    NEW_CHALLENGE_HASH_FILENAME,
                                    &parameters,
                                );
                            }
                            let new_challenge_hash_from_file = read_hash_from_file(NEW_CHALLENGE_HASH_FILENAME)?;
                            check_new_challenge_hashes_same(
                                &verified_data.data.new_challenge_hash,
                                &new_challenge_hash_from_file,
                            )?;
                            current_new_challenge_hash =
                                verified_data.data.new_challenge_hash.clone();
                        } else {
                            check_new_challenge_hashes_same(
                                &contribution.verified_data()?.data.new_challenge_hash,
                                &previous_round.as_ref().unwrap().chunks[chunk_index]
                                    .contributions
                                    .iter()
                                    .last()
                                    .unwrap()
                                    .verified_data()?
                                    .data
                                    .new_challenge_hash,
                            )?;

                            let new_challenge_filename =
                                format!("{}_{}", NEW_CHALLNGE_PREFIX_FOR_NEXT_ROUND, chunk_index);
                            copy(&new_challenge_filename, NEW_CHALLENGE_FILENAME)?;
                            remove_file_if_exists(&new_challenge_filename)?;
                            current_new_challenge_hash = contribution
                                .verified_data()?
                                .data
                                .new_challenge_hash
                                .clone();
                        }
                        continue;
                    }

                    let contributor_id = contribution.contributor_id()?;
                    if chunk_index == 0 {
                        participant_ids_from_poks.insert(contributor_id.clone());
                    }

                    // Verify the challenge and response hashes were signed by the participant.
                    let contributed_data = contribution.contributed_data()?;
                    verify_signed_data(
                        &contributed_data.data,
                        &contributed_data.signature,
                        &contributor_id,
                    )?;

                    // Verify that the challenge the participant attested they worked on is
                    // indeed the one we have as the expected computed challenge.
                    check_new_challenge_hashes_same(
                        &contributed_data.data.challenge_hash,
                        &current_new_challenge_hash,
                    )?;

                    let verified_data = contribution.verified_data()?;
                    let verifier_id = contribution.verifier_id()?;
                    // Verify the verifier challenge, response and new challenge hashes
                    // were signed by the verifier. This is not strictly necessary, but can help
                    // catch a malicious coordinator.
                    verify_signed_data(
                        &verified_data.data,
                        &verified_data.signature,
                        &verifier_id,
                    )?;

                    // Check that the verifier attested to work on the same challenge the participant
                    // attested to work on, and that the participant produced the same response as the
                    // one the verifier verified.
                    check_challenge_hashes_same(
                        &contributed_data.data.challenge_hash,
                        &verified_data.data.challenge_hash,
                    )?;
                    info!("About to check first response hashes");
                    check_response_hashes_same(
                        &contributed_data.data.response_hash,
                        &verified_data.data.response_hash,
                    )?;
                    info!("Checked first response hash");

                    let contributed_location = contribution.contributed_location()?;
                    // Download the response computed by the participant.
                    rt.block_on(download_file_from_azure_async(
                        contributed_location,
                        response_size(&parameters),
                        RESPONSE_FILENAME,
                    ))?;

                    /*if self.phase == Phase::Phase2 {
                        copy_file_if_exists(RESPONSE_FILENAME, NEW_CHALLENGE_FILENAME)?;
                    }*/

                    // Run verification between challenge and response, and produce the next new
                    // challenge.
                    if self.phase == Phase::Phase1 {
                        phase1_cli::transform_pok_and_correctness(
                            CHALLENGE_FILENAME,
                            CHALLENGE_HASH_FILENAME,
                            upgrade_correctness_check_config(
                               DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                               self.force_correctness_checks,
                            ),
                            RESPONSE_FILENAME,
                            RESPONSE_HASH_FILENAME,
                            upgrade_correctness_check_config(
                               DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                               self.force_correctness_checks,
                            ),
                            NEW_CHALLENGE_FILENAME,
                            NEW_CHALLENGE_HASH_FILENAME,
                            self.subgroup_check_mode,
                            self.ratio_check,
                            &parameters,
                        );
                    } else {
                        phase2_cli::verify(
                           CHALLENGE_FILENAME,
                           CHALLENGE_HASH_FILENAME,
                           upgrade_correctness_check_config(
                              DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                              self.force_correctness_checks,
                           ), 
                           RESPONSE_FILENAME,
                           RESPONSE_HASH_FILENAME,
                           upgrade_correctness_check_config(
                              DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                              self.force_correctness_checks,
                           ),
                           NEW_CHALLENGE_FILENAME,
                           NEW_CHALLENGE_HASH_FILENAME,
                           self.subgroup_check_mode,
                        );
                    }

                    /*if self.phase == Phase::Phase2 {
                        copy_file_if_exists(RESPONSE_HASH_FILENAME, NEW_CHALLENGE_HASH_FILENAME)?;
                    }*/

                    let challenge_hash_from_file = read_hash_from_file(CHALLENGE_HASH_FILENAME)?;
                    // Check that the challenge hash is indeed the one the participant and the verifier
                    // attested to work on.
                    check_challenge_hashes_same(
                        &verified_data.data.challenge_hash,
                        &challenge_hash_from_file,
                    )?;

                    let response_hash_from_file = read_hash_from_file(RESPONSE_HASH_FILENAME)?;
                    // Check that the response hash is indeed the one the participant attested they produced
                    // and the verifier attested to work on.
                    info!("About to check second response hashes");
                    check_response_hashes_same(
                        &verified_data.data.response_hash,
                        &response_hash_from_file,
                    )?;
                    info!("Checked second response hash");

                    let new_challenge_hash_from_file =
                        read_hash_from_file(NEW_CHALLENGE_HASH_FILENAME)?;
                    // Check that the new challenge hash is indeed the one the verifier attested to
                    // produce.
                    check_new_challenge_hashes_same(
                        &verified_data.data.new_challenge_hash,
                        &new_challenge_hash_from_file,
                    )?;

                    // Carry the produced new challenge hash to the next contribution.
                    current_new_challenge_hash = verified_data.data.new_challenge_hash.clone();

                    // This is the last contribution which we'll combine with the other last
                    // contributions, so add that to the list.
                    if i == chunk.contributions.len() - 1 {
                        let response_filename =
                            format!("{}_{}", RESPONSE_PREFIX_FOR_AGGREGATION, chunk_index);
                        copy(RESPONSE_FILENAME, &response_filename)?;
                        response_list_file.write(format!("{}\n", response_filename).as_bytes())?;
                        let new_challenge_filename =
                            format!("{}_{}", NEW_CHALLNGE_PREFIX_FOR_NEXT_ROUND, chunk_index);
                        copy(NEW_CHALLENGE_FILENAME, &new_challenge_filename)?;
                    }
                }
                info!("chunk {} verified", chunk.chunk_id);
            }

            drop(response_list_file);

            info!(
                "participants found in the transcript of round {}:\n{}",
                round_index,
                participant_ids_from_poks
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            let expected_contributor_ids: HashSet<_> =
                ceremony.contributor_ids.iter().cloned().collect();
            if expected_contributor_ids != participant_ids_from_poks {
                return Err(VerifyTranscriptError::NotAllParticipantsPresent(
                    expected_contributor_ids,
                    participant_ids_from_poks,
                )
                .into());
            }

            previous_round = Some(ceremony.clone());
            info!("Verified round {}", round_index);
        }

        info!("all rounds and chunks verified, aggregating");
        remove_file_if_exists(COMBINED_FILENAME)?;
        let current_parameters = current_parameters.unwrap();
        let parameters = create_parameters_for_chunk::<E>(&current_parameters, 0)?;
        // Combine the last contributions from each chunk into a single big contributions.
        if self.phase == Phase::Phase1 {
            phase1_cli::combine(
                RESPONSE_LIST_FILENAME, 
                COMBINED_FILENAME, 
                &parameters
            );
        } else {
            let phase2_options = self.phase2_options.as_ref().expect("Phase2 options not used while running phase2 verification"); 
            phase2_cli::combine(
                phase2_options.initial_query_filename.as_ref(),
                phase2_options.initial_full_filename.as_ref(),
                RESPONSE_LIST_FILENAME,
                COMBINED_FILENAME,
            );
        }
        info!("combined, applying beacon");
        let parameters = create_full_parameters::<E>(&current_parameters)?;
        remove_file_if_exists(COMBINED_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
        if !self.apply_beacon {
            if self.phase == Phase::Phase1 {
                phase1_cli::transform_ratios(
                    COMBINED_FILENAME,
                    upgrade_correctness_check_config(
                        DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                        self.force_correctness_checks,
                    ),
                    &parameters,
                );
            }
        } else {
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
            let final_hash_computed = hex::decode(&read_hash_from_file(
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
            )?)?;
            let final_hash_expected = hex::decode(self.transcript.final_hash.as_ref().unwrap())?;
            if final_hash_computed != final_hash_expected {
                return Err(VerifyTranscriptError::BeaconHashWasDifferentError(
                    hex::encode(&final_hash_expected),
                    hex::encode(&final_hash_computed),
                )
                .into());
            }
            info!("applied beacon, verifying");
            remove_file_if_exists(COMBINED_HASH_FILENAME)?;
            remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
            remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME)?;
            remove_file_if_exists(
                COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
            )?;
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
                   COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                   COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                   upgrade_correctness_check_config(
                       DEFAULT_VERIFY_CHECK_OUTPUT_CORRECTNESS,
                       self.force_correctness_checks,
                   ),
                   COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
                   COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
                   self.subgroup_check_mode,
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
            }
        }

        info!("Finished verification successfully!");
        Ok(())
    }
}

fn main() {
    // tracing_subscriber::fmt().json().init();

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
