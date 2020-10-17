use anyhow::Result;
use gumdrop::Options;
use phase1_cli::{
    combine, contribute, new_challenge, transform_pok_and_correctness, transform_ratios,
};
use setup_utils::{beacon_randomness, derive_rng_from_seed, from_slice};
use snark_setup_operator::{
    data_structs::{Ceremony, Response},
    error::VerifyTranscriptError,
    utils::{
        check_challenge_hashes_same, check_new_challenge_hashes_same, check_response_hashes_same,
        copy_file_if_exists, create_full_parameters, create_parameters_for_chunk, download_file,
        read_hash_from_file, remove_file_if_exists, verify_signed_data,
    },
};
use std::{
    collections::HashSet,
    fs::{copy, File},
    io::{Read, Write},
};
use tracing::info;
use zexe_algebra::{Bls12_377, PairingEngine, BW6_761};

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

const BEACON_HASH_LENGTH: usize = 32;

#[derive(Debug, Options, Clone)]
pub struct VerifyTranscriptOpts {
    #[options(
        help = "the path of the transcript json file",
        default = "transcript.json"
    )]
    pub transcript_path: String,
    #[options(help = "participant addresses to be verified")]
    pub participant_id: Vec<String>,
    #[options(help = "the beacon hash", required)]
    pub beacon_hash: String,
}

pub struct TranscriptVerifier {
    pub ceremony: Ceremony,
    pub participant_ids: Vec<String>,
    pub beacon_hash: Vec<u8>,
}

impl TranscriptVerifier {
    pub fn new(opts: &VerifyTranscriptOpts) -> Result<Self> {
        let mut transcript = String::new();
        File::open(&opts.transcript_path)
            .expect("Should have opened transcript file.")
            .read_to_string(&mut transcript)
            .expect("Should have read transcript file.");
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&transcript)?.result;

        let beacon_hash = hex::decode(&opts.beacon_hash)?;
        if beacon_hash.len() != BEACON_HASH_LENGTH {
            return Err(
                VerifyTranscriptError::BeaconHashWrongLengthError(beacon_hash.len()).into(),
            );
        }
        let verifier = Self {
            ceremony,
            participant_ids: opts.participant_id.clone(),
            beacon_hash,
        };
        Ok(verifier)
    }

    fn run<E: PairingEngine>(&self) -> Result<()> {
        // These are the participant IDs we'd like to verify are included in the transcript.
        let required_participant_ids: HashSet<_> = self.participant_ids.iter().cloned().collect();

        // These are the participant IDs we discover in the transcript.
        let mut participant_ids_from_poks = HashSet::new();

        remove_file_if_exists(RESPONSE_LIST_FILENAME)?;
        let mut response_list_file = File::create(RESPONSE_LIST_FILENAME)?;

        // Quick check - make sure the all chunks have the same number of contributions.
        // If the coordinator was honest, then each participant would have contributed
        // once to each chunk.
        if !self
            .ceremony
            .chunks
            .iter()
            .all(|c| c.contributions.len() == self.ceremony.chunks[0].contributions.len())
        {
            return Err(
                VerifyTranscriptError::NotAllChunksHaveSameNumberOfContributionsError.into(),
            );
        }

        for (chunk_index, chunk) in self.ceremony.chunks.iter().enumerate() {
            let parameters = create_parameters_for_chunk::<E>(&self.ceremony, chunk_index)?;
            let mut current_new_challenge_hash = String::new();
            for (i, contribution) in chunk.contributions.iter().enumerate() {
                // Clean up the previous contribution challenge and response.
                remove_file_if_exists(CHALLENGE_FILENAME)?;
                remove_file_if_exists(CHALLENGE_HASH_FILENAME)?;
                remove_file_if_exists(RESPONSE_FILENAME)?;
                remove_file_if_exists(RESPONSE_HASH_FILENAME)?;
                // Copy the previous contribution's new challenge output as this contribution's
                // input challenge.
                copy_file_if_exists(NEW_CHALLENGE_FILENAME, CHALLENGE_FILENAME)?;
                // Clean up the copied new challenge.
                remove_file_if_exists(NEW_CHALLENGE_FILENAME)?;
                remove_file_if_exists(NEW_CHALLENGE_HASH_FILENAME)?;

                // This is the initialization pseudo-contribution, so we verify it was
                // deterministically created by `new`.
                if i == 0 {
                    let verified_data = contribution.verified_data()?;
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
                verify_signed_data(&verified_data.data, &verified_data.signature, &verifier_id)?;

                // Check that the verifier attested to work on the same challenge the participant
                // attested to work on, and that the participant produced the same response as the
                // one the verifier verified.
                check_challenge_hashes_same(
                    &contributed_data.data.challenge_hash,
                    &verified_data.data.challenge_hash,
                )?;
                check_response_hashes_same(
                    &contributed_data.data.response_hash,
                    &verified_data.data.response_hash,
                )?;

                let contributed_location = contribution.contributed_location()?;
                // Download the response computed by the participant.
                download_file(contributed_location, RESPONSE_FILENAME)?;

                // Run verification between challenge and response, and produce the next new
                // challenge.
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
                // Check that the challenge hash is indeed the one the participant and the verifier
                // attested to work on.
                check_challenge_hashes_same(
                    &verified_data.data.challenge_hash,
                    &challenge_hash_from_file,
                )?;

                let response_hash_from_file = read_hash_from_file(RESPONSE_HASH_FILENAME)?;
                // Check that the response hash is indeed the one the participant attested they produced
                // and the verifier attested to work on.
                check_response_hashes_same(
                    &verified_data.data.response_hash,
                    &response_hash_from_file,
                )?;

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
        let parameters = create_parameters_for_chunk::<E>(&self.ceremony, 0)?;
        // Combine the last contributions from each chunk into a single big contributions.
        combine(RESPONSE_LIST_FILENAME, COMBINED_FILENAME, &parameters);
        info!("combined, applying beacon");
        let parameters = create_full_parameters::<E>(&self.ceremony)?;
        remove_file_if_exists(COMBINED_HASH_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME)?;
        remove_file_if_exists(COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME)?;
        let rng = derive_rng_from_seed(&beacon_randomness(from_slice(&self.beacon_hash)));
        // Apply the random beacon.
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
        // Verify the correctness of the random beacon.
        transform_pok_and_correctness(
            COMBINED_FILENAME,
            COMBINED_HASH_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_HASH_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_HASH_FILENAME,
            &parameters,
        );
        // Verify the consistency of the entire combined contribution, making sure that the
        // correct ratios hold between elements.
        transform_ratios(
            COMBINED_VERIFIED_POK_AND_CORRECTNESS_NEW_CHALLENGE_FILENAME,
            &parameters,
        );

        info!(
            "participants found in transcript:\n{}",
            participant_ids_from_poks
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
        if required_participant_ids.len() > 0
            && !required_participant_ids
                .iter()
                .all(|x| participant_ids_from_poks.contains(x))
        {
            return Err(VerifyTranscriptError::NotAllParticipantsPresent(
                required_participant_ids,
                participant_ids_from_poks,
            )
            .into());
        }

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
