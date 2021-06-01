use algebra::{Bls12_377, PairingEngine, BW6_761};
use anyhow::{anyhow, Result};
use ethers::core::k256::ecdsa::SigningKey;
use ethers::signers::LocalWallet;
use gumdrop::Options;
use phase1::{ContributionMode, Phase1Parameters, ProvingSystem};
#[allow(unused_imports)]
use phase1_cli::*;
#[allow(unused_imports)]
use phase2_cli::*;
use reqwest::header::AUTHORIZATION;
use secrecy::ExposeSecret;
use snark_setup_operator::data_structs::{
    Ceremony, Chunk, ChunkMetadata, Contribution, ContributionMetadata, Parameters, Response,
    SignedData, VerifiedData,
};
use snark_setup_operator::error::UtilsError;
use snark_setup_operator::utils::{
    address_to_string, compute_hash_from_file, get_authorization_value, proving_system_from_str,
    read_hash_from_file, read_keys, remove_file_if_exists, string_to_phase,
    upload_file_to_azure_with_access_key_async, upload_mode_from_str, Phase, UploadMode,
};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tracing::info;
use url::Url;

const NEW_CHALLENGE_FILENAME: &str = "new_challenge";
const NEW_CHALLENGE_HASH_FILENAME: &str = "new_challenge.hash";
const NEW_CHALLENGE_LIST_FILENAME: &str = "new_challenge_list";

#[derive(Debug, Options, Clone)]
pub struct NewCeremonyOpts {
    help: bool,
    #[options(help = "phase to be run. Must be either phase1 or phase2")]
    pub phase: String,
    #[options(help = "the server url", required)]
    pub server_url: String,
    #[options(help = "the upload mode", required)]
    pub upload_mode: String,
    #[options(help = "participants")]
    pub participant: Vec<String>,
    #[options(help = "verifiers")]
    pub verifier: Vec<String>,
    #[options(help = "deployer", required)]
    pub deployer: String,
    #[options(
        help = "the encrypted keys for the Plumo setup",
        default = "plumo.keys"
    )]
    pub keys_file: String,
    #[options(help = "storage account in azure mode")]
    pub storage_account: Option<String>,
    #[options(help = "container name in azure mode")]
    pub container: Option<String>,
    #[options(help = "access key in azure mode")]
    pub access_key: Option<String>,
    #[options(help = "output dir in direct mode")]
    pub output_dir: Option<String>,
    #[options(help = "log2 of chunk size", required)]
    pub chunk_size: usize,
    #[options(help = "powers", required)]
    pub powers: usize,
    #[options(help = "proving system", default = "groth16")]
    pub proving_system: String,
    #[options(help = "curve", default = "bw6")]
    pub curve: String,
    #[options(help = "max locks", default = "3")]
    pub max_locks: u64,
    #[options(help = "read passphrase from stdin. THIS IS UNSAFE as it doesn't use pinentry!")]
    pub unsafe_passphrase: bool,
    #[options(help = "use prepared ceremony")]
    pub prepared_ceremony: Option<String>,

    #[options(help = "file with prepared output from phase1. Only used for phase 2")]
    pub phase1_filename: Option<String>,
    #[options(help = "file with prepared circuit. Only used for phase 2")]
    pub circuit_filename: Option<String>,
}

fn build_ceremony_from_chunks(
    opts: &NewCeremonyOpts,
    chunks: &[Chunk],
    existing_contributor_ids: &[String],
    existing_verifier_ids: &[String],
) -> Result<Ceremony> {
    let chunk_size = 1 << opts.chunk_size;
    let ceremony = Ceremony {
        round: 0,
        version: 0,
        max_locks: opts.max_locks,
        shutdown_signal: false,
        attestations: Some(vec![]),
        contributor_ids: [&opts.participant, existing_contributor_ids].concat(),
        verifier_ids: [&opts.verifier, existing_verifier_ids].concat(),
        parameters: Parameters {
            proving_system: opts.proving_system.clone(),
            curve_kind: opts.curve.clone(),
            chunk_size: chunk_size,
            batch_size: chunk_size,
            power: opts.powers,
        },
        chunks: chunks.to_vec(),
        phase: opts.phase.clone(),
    };
    let filename = format!("ceremony_{}", chrono::Utc::now().timestamp_nanos());
    info!(
        "Saving ceremony with {} chunks to {}",
        chunks.len(),
        filename
    );
    let mut file = File::create(filename)?;
    file.write_all(serde_json::to_string_pretty(&ceremony)?.as_bytes())?;

    Ok(ceremony)
}

async fn run<E: PairingEngine>(opts: &NewCeremonyOpts, private_key: &[u8]) -> Result<()> {
    let phase = string_to_phase(&opts.phase)?;
    let server_url = Url::parse(opts.server_url.as_str())?.join("ceremony")?;
    let data = reqwest::get(server_url.as_str())
        .await?
        .error_for_status()?
        .text()
        .await?;
    println!("about to parse json");
    let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
    println!("parsed json");
    let deployer = opts.deployer.clone();
    let private_key = LocalWallet::from(SigningKey::new(private_key)?);
    if address_to_string(&private_key.address()) != deployer {
        return Err(anyhow!("Deployer must match the private key"));
    }
    if ceremony.version != 0
        || !ceremony
            .verifier_ids
            .contains(&address_to_string(&private_key.address()))
    {
        return Err(anyhow!("Can only initialize a ceremony with version 0 and the verifiers list must contain the address matching the private key"));
    }

    let upload_mode = upload_mode_from_str(&opts.upload_mode)?;
    let proving_system = proving_system_from_str(&opts.proving_system)?;
    let chunk_size = 1 << opts.chunk_size;
    let parameters = Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        0,
        chunk_size,
        proving_system,
        opts.powers,
        chunk_size,
    );
    // phase 1 new_challenge creates one chunk per call, phase 2 new_challenge creates all chunks
    // and returns how many have been created
    let num_chunks = if phase == Phase::Phase1 {
        match proving_system {
            ProvingSystem::Groth16 => (parameters.powers_g1_length + chunk_size - 1) / chunk_size,
            ProvingSystem::Marlin => (parameters.powers_length + chunk_size - 1) / chunk_size,
        }
    } else {
        phase2_cli::new_challenge(
            NEW_CHALLENGE_FILENAME,
            NEW_CHALLENGE_HASH_FILENAME,
            NEW_CHALLENGE_LIST_FILENAME,
            opts.chunk_size,
            &opts
                .phase1_filename
                .as_ref()
                .expect("phase1 filename not found while running phase2"),
            opts.powers,
            &opts
                .circuit_filename
                .as_ref()
                .expect("circuit filename not found when running phase2"),
        )
    };

    if let Some(prepared_ceremony) = opts.prepared_ceremony.as_ref() {
        let mut ceremony_contents = String::new();
        File::open(&prepared_ceremony)?.read_to_string(&mut ceremony_contents)?;
        let ceremony: Ceremony = serde_json::from_str::<Ceremony>(&ceremony_contents)?;
        info!("Updating ceremony");
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&private_key, "PUT", "/ceremony")?;
        client
            .put(server_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(&ceremony)
            .send()
            .await?
            .error_for_status()?;
        info!("Done!");
        return Ok(());
    }

    let mut chunks = vec![];
    for chunk_index in 0..num_chunks {
        info!("Working on chunk {}", chunk_index);
        let parameters = Phase1Parameters::<E>::new_chunk(
            ContributionMode::Chunked,
            chunk_index,
            chunk_size,
            proving_system,
            opts.powers,
            chunk_size,
        );
        if phase == Phase::Phase1 {
            remove_file_if_exists(NEW_CHALLENGE_FILENAME)?;
            remove_file_if_exists(NEW_CHALLENGE_HASH_FILENAME)?;
            phase1_cli::new_challenge(
                NEW_CHALLENGE_FILENAME,
                NEW_CHALLENGE_HASH_FILENAME,
                &parameters,
            );
        }

        let phase2_new_challenge_fname = format!("{}.{}", NEW_CHALLENGE_FILENAME, chunk_index);
        let challenge_filename = if phase == Phase::Phase1 {
            NEW_CHALLENGE_FILENAME
        } else {
            &phase2_new_challenge_fname
        };
        let new_challenge_hash_from_file = if phase == Phase::Phase1 {
            read_hash_from_file(NEW_CHALLENGE_HASH_FILENAME)?
        } else {
            compute_hash_from_file(challenge_filename)?
        };

        let round = 0;
        let path = format!("{}.{}.0", round, chunk_index);
        let location = match upload_mode {
            UploadMode::Azure => {
                let access_key = opts
                    .access_key
                    .as_ref()
                    .ok_or(UtilsError::MissingOptionErr)?;
                let storage_account = opts
                    .storage_account
                    .as_ref()
                    .ok_or(UtilsError::MissingOptionErr)?;
                let container = opts
                    .container
                    .as_ref()
                    .ok_or(UtilsError::MissingOptionErr)?;
                upload_file_to_azure_with_access_key_async(
                    challenge_filename,
                    &access_key,
                    &storage_account,
                    &container,
                    &path,
                )
                .await?;
                format!(
                    "https://{}.blob.core.windows.net/{}/{}",
                    storage_account, container, path,
                )
            }
            UploadMode::Direct => {
                let output_path = Path::new(
                    &opts
                        .output_dir
                        .as_ref()
                        .ok_or(UtilsError::MissingOptionErr)?,
                )
                .join(path);
                std::fs::copy(challenge_filename, output_path)?;
                format!(
                    "{}/chunks/{}/{}/contribution/0",
                    opts.server_url, round, chunk_index
                )
            }
            UploadMode::Auto => {
                return Err(anyhow!(
                    "Unsupported upload mode Auto in the creation of a new ceremony"
                ))
            }
        };
        let chunk = Chunk {
            chunk_id: chunk_index.to_string(),
            lock_holder: None,
            metadata: Some(ChunkMetadata {
                lock_holder_time: None
            }),
            contributions: vec![
                Contribution {
                    metadata: Some(ContributionMetadata {
                        contributed_time: None,
                        contributed_lock_holder_time: None,
                        verified_time: None,
                        verified_lock_holder_time: None,
                    }),
                    contributor_id: None,
                    contributed_location: None,
                    verifier_id: Some(deployer.clone()),
                    verified: true,
                    verified_data: Some(SignedData {
                        data: serde_json::to_value(VerifiedData {
                            challenge_hash: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                            response_hash: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                            new_challenge_hash: new_challenge_hash_from_file,
                            verification_duration: None,
                        })?,
                        signature: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                    }),
                    contributed_data: None,
                    verified_location: Some(location),
                }
            ],
        };
        chunks.push(chunk);
        build_ceremony_from_chunks(
            &opts,
            &chunks,
            &ceremony.contributor_ids,
            &ceremony.verifier_ids,
        )?;
    }

    let ceremony = build_ceremony_from_chunks(
        &opts,
        &chunks,
        &ceremony.contributor_ids,
        &ceremony.verifier_ids,
    )?;
    info!("Updating ceremony");
    let client = reqwest::Client::new();
    let authorization = get_authorization_value(&private_key, "PUT", "ceremony")?;
    client
        .put(server_url.as_str())
        .header(AUTHORIZATION, authorization)
        .json(&ceremony)
        .send()
        .await?
        .error_for_status()?;
    info!("Done!");

    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let opts: NewCeremonyOpts = NewCeremonyOpts::parse_args_default_or_exit();
    let (_, private_key, _) = read_keys(&opts.keys_file, opts.unsafe_passphrase, false)
        .expect("Should have loaded Plumo setup keys");
    match opts.curve.as_str() {
        "bw6" => {
            run::<BW6_761>(&opts, private_key.expose_secret())
                .await
                .expect("Should have run the new ceremony generation");
        }
        "bls12_377" => {
            run::<Bls12_377>(&opts, private_key.expose_secret())
                .await
                .expect("Should have run the new ceremony generation");
        }
        c => panic!("Unsupported curve {}", c),
    }
}
