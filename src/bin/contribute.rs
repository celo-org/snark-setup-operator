use snark_setup_operator::data_structs::{
    Chunk, ContributedData, ContributionUploadUrl, PlumoSetupKeys, SignedContributedData,
};
use snark_setup_operator::utils::{
    address_to_string, create_parameters_for_chunk, download_file_async, get_authorization_value,
    read_hash_from_file, remove_file_if_exists, sign_json, upload_file_direct_async,
    upload_file_to_azure_async, upload_mode_from_str, UploadMode,
};
use snark_setup_operator::{
    data_structs::{Ceremony, Response},
    error::ContributeError,
};

use anyhow::Result;
use chrono::Duration;
use ethers::types::{Address, PrivateKey};
use gumdrop::Options;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use panic_control::{spawn_quiet, ThreadResultExt};
use phase1_cli::contribute;
use rand::prelude::SliceRandom;
use reqwest::header::AUTHORIZATION;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use setup_utils::derive_rng_from_seed;
use std::collections::HashSet;
use std::io::Read;
use tokio::time::Instant;
use tracing::{error, info, warn};
use url::Url;
use zexe_algebra::{PairingEngine, BW6_761};

const CHALLENGE_FILENAME: &str = "challenge";
const CHALLENGE_HASH_FILENAME: &str = "challenge.hash";
const RESPONSE_FILENAME: &str = "response";
const RESPONSE_HASH_FILENAME: &str = "response.hash";

#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(
        help = "the encrypted keys for the Plumo setup",
        default = "plumo.keys"
    )]
    pub keys_path: String,
    #[options(help = "the storage upload mode", default = "auto")]
    pub upload_mode: String,
}

pub struct Contribute<'a> {
    pub server_url: Url,
    pub participant_id: String,
    pub private_key: PrivateKey,
    pub seed: &'a [u8],
    pub upload_mode: UploadMode,
}

impl<'a> Contribute<'a> {
    pub fn new(opts: &ContributeOpts, seed: &'a [u8], private_key: &[u8]) -> Result<Self> {
        let private_key = bincode::deserialize(private_key)?;
        let upload_mode = upload_mode_from_str(&opts.upload_mode)?;
        let contribute = Self {
            server_url: Url::parse(&opts.coordinator_url)?,
            participant_id: address_to_string(&Address::from(&private_key)),
            private_key,
            seed,
            upload_mode,
        };
        Ok(contribute)
    }

    async fn run_and_catch_errors<E: PairingEngine>(&self) -> Result<()> {
        let progress_style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .progress_chars("#>-");
        let progress_bar = ProgressBar::hidden();
        progress_bar.enable_steady_tick(1000);
        progress_bar.set_style(progress_style);
        loop {
            let result = self.run::<E>(&self.seed, &progress_bar).await;
            match result {
                Ok(_) => {
                    info!("Successfully contributed, thank you for participation! Waiting to see if you're still needed... Don't turn this off! ");
                    progress_bar.set_message("Successfully contributed, thank you for participation! Waiting to see if you're still needed... Don't turn this off!");
                }
                Err(e) => {
                    warn!("Got error from run: {}, retrying...", e);
                    progress_bar.set_message(&format!("Got error from run: {}, retrying...", e));
                }
            }
            std::thread::sleep(Duration::seconds(10).to_std()?);
        }
    }

    async fn run<E: PairingEngine>(&self, seed: &[u8], progress_bar: &ProgressBar) -> Result<()> {
        loop {
            let ceremony = self.get_ceremony().await?;
            progress_bar.set_length(ceremony.chunks.len() as u64);
            if progress_bar.is_hidden() {
                progress_bar.set_draw_target(ProgressDrawTarget::stderr());
            }
            let non_contributed_chunks = self.get_non_contributed_chunks(&ceremony)?;
            let chunk_id = match self.get_already_locked_chunk(&ceremony)? {
                Some(chunk_id) => chunk_id,
                None => {
                    let incomplete_chunks =
                        self.get_non_contributed_and_available_chunks(&ceremony)?;
                    if incomplete_chunks.len() == 0 {
                        if non_contributed_chunks.len() == 0 {
                            progress_bar.set_position(ceremony.chunks.len() as u64);
                            return Ok(());
                        } else {
                            progress_bar
                                .set_message(&format!("Waiting for an available chunk...",));
                            progress_bar.set_position(
                                (ceremony.chunks.len() - non_contributed_chunks.len()) as u64,
                            );

                            std::thread::sleep(Duration::seconds(10).to_std()?);
                            continue;
                        }
                    }
                    let chunk_id = incomplete_chunks
                        .choose(&mut rand::thread_rng())
                        .ok_or(ContributeError::CouldNotChooseChunkError)?;
                    self.lock_chunk(chunk_id).await?;
                    chunk_id.clone()
                }
            };

            let (chunk_index, chunk) = self.get_chunk(&ceremony, &chunk_id)?;
            progress_bar.set_message(&format!("Contributing to chunk {}...", chunk_id,));
            progress_bar
                .set_position((ceremony.chunks.len() - non_contributed_chunks.len()) as u64);
            remove_file_if_exists(CHALLENGE_FILENAME)?;
            remove_file_if_exists(CHALLENGE_HASH_FILENAME)?;
            let download_url = self.get_download_url_of_last_challenge(&chunk)?;
            download_file_async(&download_url, CHALLENGE_FILENAME).await?;
            let rng = derive_rng_from_seed(seed);
            let start = Instant::now();
            remove_file_if_exists(RESPONSE_FILENAME)?;
            remove_file_if_exists(RESPONSE_HASH_FILENAME)?;
            let parameters = create_parameters_for_chunk::<E>(&ceremony, chunk_index)?;
            let h = spawn_quiet(move || {
                contribute(
                    CHALLENGE_FILENAME,
                    CHALLENGE_HASH_FILENAME,
                    RESPONSE_FILENAME,
                    RESPONSE_HASH_FILENAME,
                    &parameters,
                    rng,
                );
            });
            let result = h.join();
            if !result.is_ok() {
                if let Some(panic_value) = result.panic_value_as_str() {
                    error!("Contribute failed: {}", panic_value);
                }
                return Err(ContributeError::FailedRunningContributeError.into());
            }
            let duration = start.elapsed();
            let upload_url = self.get_upload_url(&chunk_id).await?;
            let authorization = get_authorization_value(
                &self.private_key,
                "POST",
                Url::parse(&upload_url)?.path(),
            )?;

            let contributed_data = ContributedData {
                challenge_hash: read_hash_from_file(CHALLENGE_HASH_FILENAME)?,
                response_hash: read_hash_from_file(RESPONSE_HASH_FILENAME)?,
                contribution_duration: Some(duration.as_millis() as u64),
            };
            let contributed_data_value = serde_json::to_value(contributed_data)?;
            let signed_contributed_data = SignedContributedData {
                signature: sign_json(&self.private_key, &contributed_data_value)?,
                data: contributed_data_value,
            };
            match self.upload_mode {
                UploadMode::Auto => {
                    if upload_url.contains("blob.core.windows.net") {
                        upload_file_to_azure_async(RESPONSE_FILENAME, &upload_url).await?
                    } else {
                        upload_file_direct_async(&authorization, RESPONSE_FILENAME, &upload_url)
                            .await?
                    }
                }
                UploadMode::Azure => {
                    upload_file_to_azure_async(RESPONSE_FILENAME, &upload_url).await?
                }
                UploadMode::Direct => {
                    upload_file_direct_async(&authorization, RESPONSE_FILENAME, &upload_url).await?
                }
            }

            self.notify_contribution(&chunk_id, serde_json::to_value(signed_contributed_data)?)
                .await?;
        }
    }

    fn get_already_locked_chunk(&self, ceremony: &Ceremony) -> Result<Option<String>> {
        let chunk_id = ceremony
            .chunks
            .iter()
            .find(|c| c.lock_holder == Some(self.participant_id.clone()))
            .map(|c| c.chunk_id.clone());
        Ok(chunk_id)
    }

    fn get_non_contributed_chunks(&self, ceremony: &Ceremony) -> Result<Vec<String>> {
        let mut non_contributed = vec![];

        for chunk in ceremony.chunks.iter() {
            let participant_ids_in_chunk: HashSet<_> = chunk
                .contributions
                .iter()
                .map(|c| c.contributor_id.as_ref())
                .filter_map(|e| e)
                .collect();
            if !participant_ids_in_chunk.contains(&self.participant_id) {
                non_contributed.push(chunk.chunk_id.clone());
            }
        }

        Ok(non_contributed)
    }

    fn get_non_contributed_and_available_chunks(&self, ceremony: &Ceremony) -> Result<Vec<String>> {
        let mut non_contributed = vec![];

        for chunk in ceremony.chunks.iter().filter(|c| c.lock_holder.is_none()) {
            if !chunk.contributions.iter().all(|c| c.verified) {
                continue;
            }
            let participant_ids_in_chunk: HashSet<_> = chunk
                .contributions
                .iter()
                .filter(|c| c.verified)
                .map(|c| c.contributor_id.as_ref())
                .filter_map(|e| e)
                .collect();
            if !participant_ids_in_chunk.contains(&self.participant_id) {
                non_contributed.push(chunk.chunk_id.clone());
            }
        }

        Ok(non_contributed)
    }

    fn get_download_url_of_last_challenge(&self, chunk: &Chunk) -> Result<String> {
        let url = chunk
            .contributions
            .iter()
            .last()
            .ok_or(ContributeError::ContributionListWasEmptyForChunkID(
                chunk.chunk_id.to_string(),
            ))?
            .verified_location
            .clone()
            .ok_or(ContributeError::VerifiedLocationWasNoneForChunkID(
                chunk.chunk_id.to_string(),
            ))?;
        Ok(url)
    }

    fn get_chunk(&self, ceremony: &Ceremony, chunk_id: &str) -> Result<(usize, Chunk)> {
        let chunk = ceremony
            .chunks
            .iter()
            .find(|c| c.chunk_id == chunk_id)
            .ok_or(ContributeError::CouldNotFindChunkWithIDError(
                chunk_id.to_string(),
            ))?;
        Ok((chunk_id.parse::<usize>()?, chunk.clone()))
    }

    async fn get_ceremony(&self) -> Result<Ceremony> {
        let ceremony_url = self.server_url.join("ceremony")?;
        let response = reqwest::get(ceremony_url.as_str())
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
        Ok(ceremony)
    }

    async fn lock_chunk(&self, chunk_id: &str) -> Result<()> {
        let lock_path = format!("/chunks/{}/lock", chunk_id);
        let lock_chunk_url = self.server_url.join(&lock_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &lock_path)?;
        client
            .post(lock_chunk_url.as_str())
            .header(AUTHORIZATION, authorization)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn get_upload_url(&self, chunk_id: &str) -> Result<String> {
        let upload_request_path = format!("/chunks/{}/contribution", chunk_id);
        let upload_request_url = self.server_url.join(&upload_request_path)?;
        let client = reqwest::Client::new();
        let authorization =
            get_authorization_value(&self.private_key, "GET", &upload_request_path)?;
        let response: Response<ContributionUploadUrl> = client
            .get(upload_request_url.as_str())
            .header(AUTHORIZATION, authorization)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.result.write_url)
    }

    async fn notify_contribution(&self, chunk_id: &str, body: serde_json::Value) -> Result<()> {
        let lock_path = format!("/chunks/{}/contribution", chunk_id);
        let lock_chunk_url = self.server_url.join(&lock_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &lock_path)?;
        client
            .post(lock_chunk_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

fn decrypt(passphrase: &SecretString, encrypted: &str) -> Result<Vec<u8>> {
    let decoded = SecretVec::new(hex::decode(encrypted)?);
    let decryptor = age::Decryptor::new(decoded.expose_secret().as_slice())?;
    let mut output = vec![];
    if let age::Decryptor::Passphrase(decryptor) = decryptor {
        let mut reader = decryptor.decrypt(passphrase, None)?;
        reader.read_to_end(&mut output)?;
    } else {
        return Err(ContributeError::UnsupportedDecryptorError.into());
    }

    Ok(output)
}

fn read_keys(keys_path: &str) -> Result<(SecretVec<u8>, SecretVec<u8>)> {
    let mut contents = String::new();
    std::fs::File::open(&keys_path)?.read_to_string(&mut contents)?;
    let keys: PlumoSetupKeys = serde_json::from_str(&contents)?;
    let passphrase =
        age::cli_common::read_secret("Enter your Plumo setup passphrase", "Passphrase", None)
            .map_err(|_| ContributeError::CouldNotReadPassphraseError)?;
    let plumo_seed = SecretVec::new(decrypt(&passphrase, &keys.encrypted_seed)?);
    let plumo_private_key = SecretVec::new(decrypt(&passphrase, &keys.encrypted_private_key)?);

    Ok((plumo_seed, plumo_private_key))
}

#[tokio::main]
async fn main() {
    let appender = tracing_appender::rolling::never(".", "snark-setup.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt().with_writer(non_blocking).init();

    let opts: ContributeOpts = ContributeOpts::parse_args_default_or_exit();
    let (seed, private_key) =
        read_keys(&opts.keys_path).expect("Should have loaded Plumo setup keys");

    let contribute = Contribute::new(&opts, seed.expose_secret(), private_key.expose_secret())
        .expect("Should have been able to create a contribute.");
    match contribute.run_and_catch_errors::<BW6_761>().await {
        Err(e) => info!("Got error from contribute: {}", e.to_string()),
        _ => {}
    }
}
