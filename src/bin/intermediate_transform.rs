use algebra::{Bls12_377, PairingEngine, BW6_761};
use anyhow::Result;
use gumdrop::Options;
#[allow(unused_imports)]
use phase1_cli::*;
use setup_utils::converters::{batch_exp_mode_from_str, subgroup_check_mode_from_str};
use setup_utils::{
    BatchExpMode,
    SubgroupCheckMode,
};
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{
        create_full_parameters,
        remove_file_if_exists,
        BEACON_HASH_LENGTH,
    },
};
use std::{
    fs::File,
    io::Read,
};

const PHASE2_FILENAME: &str = "phase2_init";
const COMBINED_FILENAME: &str = "combined";

#[derive(Debug, Options, Clone)]
pub struct IntermediateTransformOpts {
    help: bool,
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

    #[options(help = "number powers used")]
    pub num_powers: usize,
}

pub struct IntermediateTransform {
    pub transcript: Transcript,
    pub apply_beacon: bool,
    pub beacon_hash: Vec<u8>,
    pub force_correctness_checks: bool,
    pub batch_exp_mode: BatchExpMode,
    pub subgroup_check_mode: SubgroupCheckMode,
    pub ratio_check: bool,
    pub num_powers: usize,
}

impl IntermediateTransform {
    pub fn new(opts: &IntermediateTransformOpts) -> Result<Self> {
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
        let parameters = Self {
            transcript,
            beacon_hash,
            apply_beacon: opts.apply_beacon,
            force_correctness_checks: opts.force_correctness_checks,
            batch_exp_mode: opts.batch_exp_mode,
            subgroup_check_mode: opts.subgroup_check_mode,
            ratio_check: !opts.skip_ratio_check,
            num_powers: opts.num_powers,
        };
        Ok(parameters)
    }

    fn run<E: PairingEngine>(&self) -> Result<()> {
        let ceremony = self.transcript.rounds.iter().last().expect("Round not found in transcript");
        let parameters = create_full_parameters::<E>(&ceremony.parameters)?;

        remove_file_if_exists(PHASE2_FILENAME)?;
        phase1_cli::prepare_phase2(
            PHASE2_FILENAME,
            COMBINED_FILENAME,
            self.num_powers,
            &parameters,
        )?;

        Ok(())
    }
}

fn main() {
    tracing_subscriber::fmt().json().init();

    let opts: IntermediateTransformOpts = IntermediateTransformOpts::parse_args_default_or_exit();

    let transformer = IntermediateTransform::new(&opts)
        .expect("Should have been able to create a transcript verifier");
    (match opts.curve.as_str() {
        "bw6" => transformer.run::<BW6_761>(),
        "bls12_377" => transformer.run::<Bls12_377>(),
        _ => Err(VerifyTranscriptError::UnsupportedCurveKindError(opts.curve.clone()).into()),
    })
    .expect("Should have run successfully");
}
