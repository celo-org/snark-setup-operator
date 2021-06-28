use algebra::{Bls12_377, PairingEngine, BW6_761};
use anyhow::Result;
use gumdrop::Options;
#[allow(unused_imports)]
use phase1_cli::*;
use snark_setup_operator::transcript_data_structs::Transcript;
use snark_setup_operator::{
    error::VerifyTranscriptError,
    utils::{create_full_parameters, remove_file_if_exists},
};
use std::{fs::File, io::Read};

const PHASE2_FILENAME: &str = "phase2_init";
const COMBINED_FILENAME: &str = "combined";

#[derive(Debug, Options, Clone)]
pub struct IntermediateTransformOpts {
    help: bool,
    #[options(help = "the path of the transcript json file", default = "transcript")]
    pub transcript_path: String,
    #[options(help = "curve", default = "bw6")]
    pub curve: String,
    #[options(help = "number powers used")]
    pub num_powers: usize,
}

pub struct IntermediateTransform {
    pub transcript: Transcript,
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

        let parameters = Self {
            transcript,
            num_powers: opts.num_powers,
        };
        Ok(parameters)
    }

    fn run<E: PairingEngine>(&self) -> Result<()> {
        let ceremony = self
            .transcript
            .rounds
            .iter()
            .last()
            .expect("Round not found in transcript");
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
