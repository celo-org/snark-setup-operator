use anyhow::{anyhow, Result};
use ethers::core::k256::ecdsa::SigningKey;
use ethers::signers::LocalWallet;
use gumdrop::Options;
use phase1::{ContributionMode, Phase1Parameters, ProvingSystem};
use phase1_cli::new_challenge;
use reqwest::header::AUTHORIZATION;
use secrecy::ExposeSecret;
use snark_setup_operator::data_structs::{
    Ceremony, Chunk, ChunkMetadata, Contribution, ContributionMetadata, Parameters, Response,
    SignedData, VerifiedData,
};
use snark_setup_operator::error::UtilsError;
use snark_setup_operator::utils::{
    address_to_string, get_authorization_value, proving_system_from_str, read_hash_from_file,
    read_keys, remove_file_if_exists, upload_file_to_azure_with_access_key_async,
    upload_mode_from_str, UploadMode,
};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tracing::info;
use url::Url;
use zexe_algebra::{Bls12_377, PairingEngine, BW6_761};

const NEW_CHALLENGE_FILENAME: &str = "new_challenge";
const NEW_CHALLENGE_HASH_FILENAME: &str = "new_challenge.hash";

#[derive(Debug, Options, Clone)]
pub struct NewCeremonyOpts {
    help: bool,
    #[options(help = "the server url", required)]
    pub server_url: String,
    #[options(help = "the upload mode", required)]
    pub upload_mode: String,
    #[options(help = "participants")]
    pub participant: Vec<String>,
    #[options(help = "verifiers", required)]
    pub verifier: Vec<String>,
    #[options(
        help = "the encrypted keys for the Plumo setup",
        default = "plumo.keys"
    )]
    pub keys_path: String,
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
}

fn build_ceremony_from_chunks(opts: &NewCeremonyOpts, chunks: &[Chunk]) -> Result<Ceremony> {
    let chunk_size = 1 << opts.chunk_size;
    let ceremony = Ceremony {
        round: 0,
        version: 0,
        max_locks: opts.max_locks,
        shutdown_signal: false,
        contributor_ids: opts.participant.clone(),
        verifier_ids: opts.verifier.clone(),
        parameters: Parameters {
            proving_system: opts.proving_system.clone(),
            curve_kind: opts.curve.clone(),
            chunk_size: chunk_size,
            batch_size: chunk_size,
            power: opts.powers,
        },
        chunks: chunks.to_vec(),
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
    let server_url = Url::parse(opts.server_url.as_str())?.join("ceremony")?;
    let data = reqwest::get(server_url.as_str())
        .await?
        .error_for_status()?
        .text()
        .await?;
    let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
    let private_key = LocalWallet::from(SigningKey::new(private_key)?);
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
    let num_chunks = match proving_system {
        ProvingSystem::Groth16 => (parameters.powers_g1_length + chunk_size - 1) / chunk_size,
        ProvingSystem::Marlin => (parameters.powers_length + chunk_size - 1) / chunk_size,
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

    let verifier = opts.verifier.first().ok_or(UtilsError::MissingOptionErr)?;
    let mut chunks = vec![];
    for chunk_index in 0..num_chunks {
        info!("Working on chunk {}", chunk_index);
        remove_file_if_exists(NEW_CHALLENGE_FILENAME)?;
        remove_file_if_exists(NEW_CHALLENGE_HASH_FILENAME)?;
        let parameters = Phase1Parameters::<E>::new_chunk(
            ContributionMode::Chunked,
            chunk_index,
            chunk_size,
            proving_system,
            opts.powers,
            chunk_size,
        );
        new_challenge(
            NEW_CHALLENGE_FILENAME,
            NEW_CHALLENGE_HASH_FILENAME,
            &parameters,
        );

        let new_challenge_hash_from_file = read_hash_from_file(NEW_CHALLENGE_HASH_FILENAME)?;

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
                    NEW_CHALLENGE_FILENAME,
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
                std::fs::copy(NEW_CHALLENGE_FILENAME, output_path)?;
                format!(
                    "{}/chunks/{}/{}/contribution/0",
                    round, opts.server_url, chunk_index
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
                    verifier_id: Some(verifier.clone()),
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
        build_ceremony_from_chunks(&opts, &chunks)?;
    }

    let ceremony = build_ceremony_from_chunks(&opts, &chunks)?;
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
    let (_, private_key) = read_keys(&opts.keys_path, opts.unsafe_passphrase, false)
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
