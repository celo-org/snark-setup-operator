use snark_setup_operator::data_structs::{
    Chunk, ContributedData, ContributionUploadUrl, FilteredChunks, PlumoSetupKeys, SignedData, VerifiedData,
};
use snark_setup_operator::utils::{
    address_to_string, create_parameters_for_chunk, download_file_async, get_authorization_value,
    participation_mode_from_str, read_hash_from_file, remove_file_if_exists, sign_json,
    upload_file_direct_async, upload_file_to_azure_async, upload_mode_from_str, ParticipationMode,
    UploadMode,
};
use snark_setup_operator::{
    data_structs::{Ceremony, Response},
    error::ContributeError,
};

use anyhow::Result;
use chrono::Duration;
use ethers::types::{Address, PrivateKey};
use gumdrop::Options;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use panic_control::{spawn_quiet, ThreadResultExt};
use phase1_cli::{contribute, transform_pok_and_correctness};
use rand::prelude::SliceRandom;
use reqwest::header::AUTHORIZATION;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use setup_utils::derive_rng_from_seed;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::ops::Deref;
use std::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;
use zexe_algebra::{PairingEngine, BW6_761};

const CHALLENGE_FILENAME: &str = "challenge";
const CHALLENGE_HASH_FILENAME: &str = "challenge.hash";
const RESPONSE_FILENAME: &str = "response";
const RESPONSE_HASH_FILENAME: &str = "response.hash";
const NEW_CHALLENGE_FILENAME: &str = "new_challenge";
const NEW_CHALLENGE_HASH_FILENAME: &str = "new_challenge.hash";

const DELAY_AFTER_ERROR_DURATION_SECS: i64 = 5;
const DELAY_WAIT_FOR_PIPELINE_SECS: i64 = 5;
const DELAY_POLL_CEREMONY_SECS: i64 = 5;

lazy_static! {
    static ref PIPELINE: RwLock<HashMap<PipelineLane, Vec<String>>> = {
        let mut map = HashMap::new();
        map.insert(PipelineLane::Download, Vec::new());
        map.insert(PipelineLane::Process, Vec::new());
        map.insert(PipelineLane::Upload, Vec::new());
        RwLock::new(map)
    };
    static ref SEED: RwLock<Option<SecretVec<u8>>> = RwLock::new(None);
}

#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    pub help: bool,
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
    #[options(help = "participation mode", default = "contribute")]
    pub participation_mode: String,
    #[options(help = "don't use pipelining")]
    pub disable_pipelining: bool,
    #[options(help = "maximum tasks in the download lane", default = "1")]
    pub max_in_download_lane: usize,
    #[options(help = "maximum tasks in the process lane", default = "1")]
    pub max_in_process_lane: usize,
    #[options(help = "maximum tasks in the upload lane", default = "1")]
    pub max_in_upload_lane: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PipelineLane {
    Download,
    Process,
    Upload,
}

impl std::fmt::Display for PipelineLane {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone)]
pub struct Contribute {
    pub server_url: Url,
    pub participant_id: String,
    pub private_key: PrivateKey,
    pub upload_mode: UploadMode,
    pub participation_mode: ParticipationMode,
    pub max_in_download_lane: usize,
    pub max_in_process_lane: usize,
    pub max_in_upload_lane: usize,
    pub challenge_filename: String,
    pub challenge_hash_filename: String,
    pub response_filename: String,
    pub response_hash_filename: String,
    pub new_challenge_filename: String,
    pub new_challenge_hash_filename: String,
    pub disable_pipelining: bool,

    // This is the only mutable state we hold.
    pub chosen_chunk_id: Option<String>,
}

impl Contribute {
    pub fn new(opts: &ContributeOpts, private_key: &[u8]) -> Result<Self> {
        let private_key = bincode::deserialize(private_key)?;
        let upload_mode = upload_mode_from_str(&opts.upload_mode)?;
        let participation_mode = participation_mode_from_str(&opts.participation_mode)?;
        let contribute = Self {
            server_url: Url::parse(&opts.coordinator_url)?,
            participant_id: address_to_string(&Address::from(&private_key)),
            private_key,
            upload_mode,
            participation_mode,
            max_in_download_lane: opts.max_in_download_lane,
            max_in_process_lane: opts.max_in_process_lane,
            max_in_upload_lane: opts.max_in_upload_lane,
            challenge_filename: CHALLENGE_FILENAME.to_string(),
            challenge_hash_filename: CHALLENGE_HASH_FILENAME.to_string(),
            response_filename: RESPONSE_FILENAME.to_string(),
            response_hash_filename: RESPONSE_HASH_FILENAME.to_string(),
            new_challenge_filename: NEW_CHALLENGE_FILENAME.to_string(),
            new_challenge_hash_filename: NEW_CHALLENGE_HASH_FILENAME.to_string(),
            disable_pipelining: opts.disable_pipelining,

            chosen_chunk_id: None,
        };
        Ok(contribute)
    }

    pub fn clone_with_new_filenames(&self, index: usize) -> Self {
        let mut cloned = self.clone();
        cloned.challenge_filename = format!("{}_{}", self.challenge_filename, index);
        cloned.challenge_hash_filename = format!("{}_{}", self.challenge_hash_filename, index);
        cloned.response_filename = format!("{}_{}", self.response_filename, index);
        cloned.response_hash_filename = format!("{}_{}", self.response_hash_filename, index);
        cloned.new_challenge_filename = format!("{}_{}", self.new_challenge_filename, index);
        cloned.new_challenge_hash_filename =
            format!("{}_{}", self.new_challenge_hash_filename, index);

        cloned
    }

    async fn run_ceremony_initialization_and_get_max_locks(&self) -> Result<u64> {
        let ceremony = self.get_ceremony().await?;
        self.release_locked_chunks(&ceremony).await?;

        Ok(ceremony.max_locks)
    }

    async fn run_and_catch_errors<E: PairingEngine>(&self) -> Result<()> {
        let delay_after_error_duration =
            Duration::seconds(DELAY_AFTER_ERROR_DURATION_SECS).to_std()?;
        let delay_poll_ceremony_duration = Duration::seconds(DELAY_POLL_CEREMONY_SECS).to_std()?;
        let progress_bar = ProgressBar::new(0);
        let progress_style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .progress_chars("#>-");
        progress_bar.enable_steady_tick(1000);
        progress_bar.set_style(progress_style);
        progress_bar.set_message("Getting initial data from the server...");
        let max_locks_from_ceremony;
        loop {
            let max_locks = self.run_ceremony_initialization_and_get_max_locks().await;
            match max_locks {
                Ok(max_locks) => {
                    max_locks_from_ceremony = max_locks;
                    break;
                }
                Err(e) => {
                    warn!("Got error from ceremony initialization: {}", e);
                    progress_bar
                        .set_message(&format!("Got error from ceremony initialization: {}", e));
                    tokio::time::delay_for(delay_after_error_duration).await;
                }
            }
        }
        let total_tasks = if self.disable_pipelining {
            1
        } else {
            std::cmp::min(
                self.max_in_download_lane + self.max_in_process_lane + self.max_in_upload_lane,
                max_locks_from_ceremony as usize,
            )
        };
        let mut futures = vec![];

        let updater = self.clone();
        tokio::spawn(async move {
            loop {
                match updater.status_updater(progress_bar.clone()).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Got error from updater: {}", e);
                        progress_bar.set_message(&format!(
                            "Could not update status: {}",
                            e.to_string().trim()
                        ));
                    }
                }
                tokio::time::delay_for(delay_poll_ceremony_duration).await;
            }
        });
        for i in 0..total_tasks {
            let delay_duration = Duration::seconds(DELAY_AFTER_ERROR_DURATION_SECS).to_std()?;
            let mut cloned = self.clone_with_new_filenames(i);
            let jh = tokio::spawn(async move {
                loop {
                    let result = cloned.run::<E>().await;
                    match result {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Got error from run: {}, retrying...", e);
                            if let Some(chunk_id) = cloned.chosen_chunk_id.as_ref() {
                                cloned
                                    .remove_chunk_id_from_lane_if_exists(
                                        &PipelineLane::Download,
                                        &chunk_id,
                                    )
                                    .expect("Should have removed chunk ID from lane");
                                cloned
                                    .remove_chunk_id_from_lane_if_exists(
                                        &PipelineLane::Process,
                                        &chunk_id,
                                    )
                                    .expect("Should have removed chunk ID from lane");
                                cloned
                                    .remove_chunk_id_from_lane_if_exists(
                                        &PipelineLane::Upload,
                                        &chunk_id,
                                    )
                                    .expect("Should have removed chunk ID from lane");
                            }
                        }
                    }
                    tokio::time::delay_for(delay_duration).await;
                }
            });
            futures.push(jh);
        }

        futures::future::try_join_all(futures).await?;

        Ok(())
    }

    async fn wait_for_available_spot_in_lane(&self, lane: &PipelineLane) -> Result<()> {
        let max_in_lane = match *lane {
            PipelineLane::Download => self.max_in_download_lane,
            PipelineLane::Process => self.max_in_process_lane,
            PipelineLane::Upload => self.max_in_upload_lane,
        };
        loop {
            {
                let pipeline = PIPELINE
                    .read()
                    .expect("Should have opened pipeline for reading");
                if pipeline
                    .get(lane)
                    .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?
                    .len()
                    < max_in_lane
                {
                    return Ok(());
                }
            }
            tokio::time::delay_for(Duration::seconds(DELAY_POLL_CEREMONY_SECS).to_std()?).await;
        }
    }

    fn get_pipeline_snapshot(&self) -> Result<HashMap<PipelineLane, Vec<String>>> {
        let pipeline = PIPELINE
            .read()
            .expect("Should have opened pipeline for reading");

        Ok(pipeline.clone())
    }

    async fn status_updater(&self, progress_bar: ProgressBar) -> Result<()> {
        let chunk_info = self.get_chunk_info().await?;
        let num_chunks = chunk_info.chunks.len();
        progress_bar.set_length(num_chunks as u64);
        let non_contributed_chunks =
            self.get_non_contributed_chunks(&chunk_info)?;
        

        let participant_locked_chunks = self.get_participant_locked_chunks_display(&chunk_info)?;
        if participant_locked_chunks.len() > 0 {
            progress_bar.set_message(&format!(
                "{} {} {}...",
                match self.participation_mode {
                    ParticipationMode::Contribute => "Contributing to",
                    ParticipationMode::Verify => "Verifying",
                },
                if participant_locked_chunks.len() > 1 {
                    "chunks"
                } else {
                    "chunk"
                },
                participant_locked_chunks.join(", "),
            ));
            progress_bar
                .set_position((num_chunks - non_contributed_chunks.len()) as u64);
        } else if non_contributed_chunks.len() == 0 {
            info!("Successfully contributed, thank you for participation! Waiting to see if you're still needed... Don't turn this off! ");
            progress_bar.set_position(num_chunks as u64);
            progress_bar.set_message("Successfully contributed, thank you for participation! Waiting to see if you're still needed... Don't turn this off!");
        } else {
            progress_bar
                .set_position((num_chunks - non_contributed_chunks.len()) as u64);
            progress_bar.set_message(&format!("Waiting for an available chunk...",));
        }

        Ok(())
    }

    fn choose_chunk_id(&self, ceremony: &FilteredChunks) -> Result<String> {
        let chunk_ids_from_pipeline: HashSet<String> = {
            let mut chunk_ids = vec![];
            let pipeline = self.get_pipeline_snapshot()?;
            for lane in &[
                PipelineLane::Download,
                PipelineLane::Process,
                PipelineLane::Upload,
            ] {
                for chunk_id in pipeline
                    .get(lane)
                    .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?
                {
                    chunk_ids.push(chunk_id.clone());
                }
            }
            chunk_ids.into_iter().collect()
        };
        let locked_chunk_ids_from_ceremony: HashSet<String> = {
            ceremony
                .chunks
                .iter()
                .filter(|c| c.lock_holder == Some(self.participant_id.clone()))
                .map(|c| c.chunk_id.clone())
                .collect()
        };
        for locked_chunk_id in locked_chunk_ids_from_ceremony {
            if !chunk_ids_from_pipeline.contains(&locked_chunk_id) {
                return Ok(locked_chunk_id);
            }
        }

        let incomplete_chunks =
            self.get_non_contributed_and_available_chunks(&ceremony)?;
        Ok(incomplete_chunks
            .choose(&mut rand::thread_rng())
            .ok_or(ContributeError::CouldNotChooseChunkError)?
            .clone())
    }

    fn add_chunk_id_to_download_lane(&self, chunk_id: &str) -> Result<bool> {
        let lane = &PipelineLane::Download;
        let max_in_lane = match *lane {
            PipelineLane::Download => self.max_in_download_lane,
            PipelineLane::Process => self.max_in_process_lane,
            PipelineLane::Upload => self.max_in_upload_lane,
        };
        let mut pipeline = PIPELINE
            .write()
            .expect("Should have opened pipeline for writing");

        let lane_list = pipeline
            .get_mut(lane)
            .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?;
        if lane_list.contains(&chunk_id.to_string()) || lane_list.len() >= max_in_lane {
            return Ok(false);
        }
        lane_list.push(chunk_id.to_string());
        debug!(
            "Chunk ID {} added successfully to lane {}. Current pipeline is: {:?}",
            chunk_id,
            lane,
            pipeline.deref()
        );
        Ok(true)
    }

    fn remove_chunk_id_from_lane_if_exists(
        &self,
        lane: &PipelineLane,
        chunk_id: &str,
    ) -> Result<()> {
        let mut pipeline = PIPELINE
            .write()
            .expect("Should have opened pipeline for writing");

        let lane_list = pipeline
            .get_mut(lane)
            .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?;
        if !lane_list.contains(&chunk_id.to_string()) {
            return Ok(());
        }
        lane_list.retain(|c| c.as_str() != chunk_id);
        debug!(
            "Chunk ID {} removed successfully from lane {}. Current pipeline is: {:?}",
            chunk_id,
            lane,
            pipeline.deref()
        );
        Ok(())
    }

    async fn move_chunk_id_from_lane_to_lane(
        &self,
        from: &PipelineLane,
        to: &PipelineLane,
        chunk_id: &str,
    ) -> Result<bool> {
        let max_in_lane = match *to {
            PipelineLane::Download => self.max_in_download_lane,
            PipelineLane::Process => self.max_in_process_lane,
            PipelineLane::Upload => self.max_in_upload_lane,
        };
        {
            let mut pipeline = PIPELINE
                .write()
                .expect("Should have opened pipeline for writing");

            {
                let to_list = pipeline
                    .get_mut(to)
                    .ok_or(ContributeError::LaneWasNullError(to.to_string()))?;

                if to_list.len() >= max_in_lane {
                    return Ok(false);
                }
            }
            {
                let from_list = pipeline
                    .get_mut(from)
                    .ok_or(ContributeError::LaneWasNullError(from.to_string()))?;
                if !from_list.contains(&chunk_id.to_string()) {
                    return Err(ContributeError::LaneDidNotContainChunkWithIDError(
                        from.to_string(),
                        chunk_id.to_string(),
                    )
                    .into());
                }
                from_list.retain(|c| c.as_str() != chunk_id);
            }

            {
                let to_list = pipeline
                    .get_mut(to)
                    .ok_or(ContributeError::LaneWasNullError(to.to_string()))?;

                if to_list.contains(&chunk_id.to_string()) {
                    return Err(ContributeError::LaneAlreadyContainsChunkWithIDError(
                        to.to_string(),
                        chunk_id.to_string(),
                    )
                    .into());
                }
                to_list.push(chunk_id.to_string());
            }
            debug!(
                "Chunk ID {} moved successfully from lane {} to lane {}. Current pipeline is: {:?}",
                chunk_id,
                from,
                to,
                pipeline.deref()
            );
            Ok(true)
        }
    }

    async fn wait_and_move_chunk_id_from_lane_to_lane(
        &self,
        from: &PipelineLane,
        to: &PipelineLane,
        chunk_id: &str,
    ) -> Result<()> {
        loop {
            match self
                .move_chunk_id_from_lane_to_lane(from, to, chunk_id)
                .await?
            {
                true => return Ok(()),
                false => {
                    tokio::time::delay_for(
                        Duration::seconds(DELAY_WAIT_FOR_PIPELINE_SECS).to_std()?,
                    )
                    .await;
                }
            }
        }
    }

    async fn run<E: PairingEngine>(&mut self) -> Result<()> {
        loop {
            self.wait_for_available_spot_in_lane(&PipelineLane::Download)
                .await?;
            let chunk_info = self.get_chunk_info().await?;

            let non_contributed_chunks =
                self.get_non_contributed_chunks(&chunk_info)?;

            let incomplete_chunks =
                self.get_non_contributed_and_available_chunks(&chunk_info)?;
            if incomplete_chunks.len() == 0 {
                if non_contributed_chunks.len() == 0 {
                    remove_file_if_exists(&self.challenge_filename)?;
                    remove_file_if_exists(&self.challenge_hash_filename)?;
                    remove_file_if_exists(&self.response_filename)?;
                    remove_file_if_exists(&self.response_hash_filename)?;
                    remove_file_if_exists(&self.new_challenge_filename)?;
                    remove_file_if_exists(&self.new_challenge_hash_filename)?;
                    return Ok(());
                } else {
                    tokio::time::delay_for(
                        Duration::seconds(DELAY_WAIT_FOR_PIPELINE_SECS).to_std()?,
                    )
                    .await;
                    continue;
                }
            }
            let chunk_id = self.choose_chunk_id(&chunk_info)?;
            if !self.add_chunk_id_to_download_lane(&chunk_id)? {
                continue;
            }
            self.chosen_chunk_id = Some(chunk_id.to_string());
            self.lock_chunk(&chunk_id).await?;

            let (chunk_index, chunk) = self.get_chunk(&chunk_id).await?;

            let (file_to_upload, contributed_or_verified_data) = match self.participation_mode {
                ParticipationMode::Contribute => {
                    remove_file_if_exists(&self.challenge_filename)?;
                    remove_file_if_exists(&self.challenge_hash_filename)?;
                    let download_url = self.get_download_url_of_last_challenge(&chunk)?;
                    download_file_async(&download_url, &self.challenge_filename).await?;
                    self.wait_and_move_chunk_id_from_lane_to_lane(
                        &PipelineLane::Download,
                        &PipelineLane::Process,
                        &chunk_id,
                    )
                    .await?;
                    let seed = SEED.read().expect("Should have been able to read seed");
                    let exposed_seed = seed
                        .as_ref()
                        .ok_or(ContributeError::SeedWasNoneError)
                        .expect("Seed should not have been none")
                        .expose_secret();
                    let rng = derive_rng_from_seed(&exposed_seed[..]);
                    let start = Instant::now();
                    remove_file_if_exists(&self.response_filename)?;
                    remove_file_if_exists(&self.response_hash_filename)?;
                    let parameters = create_parameters_for_chunk::<E>(&chunk_info.parameters, chunk_index)?;
                    let (
                        challenge_filename,
                        challenge_hash_filename,
                        response_filename,
                        response_hash_filename,
                    ) = (
                        self.challenge_filename.clone(),
                        self.challenge_hash_filename.clone(),
                        self.response_filename.clone(),
                        self.response_hash_filename.clone(),
                    );
                    let h = spawn_quiet(move || {
                        contribute(
                            &challenge_filename,
                            &challenge_hash_filename,
                            &response_filename,
                            &response_hash_filename,
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
                    let contributed_data = ContributedData {
                        challenge_hash: read_hash_from_file(&self.challenge_hash_filename)?,
                        response_hash: read_hash_from_file(&self.response_hash_filename)?,
                        contribution_duration: Some(duration.as_millis() as u64),
                    };

                    (
                        &self.response_filename,
                        serde_json::to_value(contributed_data)?,
                    )
                }
                ParticipationMode::Verify => {
                    remove_file_if_exists(&self.challenge_filename)?;
                    remove_file_if_exists(&self.challenge_hash_filename)?;
                    remove_file_if_exists(&self.response_filename)?;
                    remove_file_if_exists(&self.response_hash_filename)?;
                    let challenge_download_url =
                        self.get_download_url_of_last_challenge_for_verifying(&chunk)?;
                    download_file_async(&challenge_download_url, &self.challenge_filename).await?;
                    let response_download_url = self.get_download_url_of_last_response(&chunk)?;
                    download_file_async(&response_download_url, &self.response_filename).await?;
                    self.wait_and_move_chunk_id_from_lane_to_lane(
                        &PipelineLane::Download,
                        &PipelineLane::Process,
                        &chunk_id,
                    )
                    .await?;
                    let start = Instant::now();
                    remove_file_if_exists(&self.new_challenge_filename)?;
                    remove_file_if_exists(&self.new_challenge_hash_filename)?;
                    let parameters = create_parameters_for_chunk::<E>(&chunk_info.parameters, chunk_index)?;

                    let (
                        challenge_filename,
                        challenge_hash_filename,
                        response_filename,
                        response_hash_filename,
                        new_challenge_filename,
                        new_challenge_hash_filename,
                    ) = (
                        self.challenge_filename.clone(),
                        self.challenge_hash_filename.clone(),
                        self.response_filename.clone(),
                        self.response_hash_filename.clone(),
                        self.new_challenge_filename.clone(),
                        self.new_challenge_hash_filename.clone(),
                    );
                    let h = spawn_quiet(move || {
                        transform_pok_and_correctness(
                            &challenge_filename,
                            &challenge_hash_filename,
                            &response_filename,
                            &response_hash_filename,
                            &new_challenge_filename,
                            &new_challenge_hash_filename,
                            &parameters,
                        );
                    });
                    let result = h.join();
                    if !result.is_ok() {
                        if let Some(panic_value) = result.panic_value_as_str() {
                            error!("Verification failed: {}", panic_value);
                        }
                        return Err(ContributeError::FailedRunningVerificationError.into());
                    }
                    let duration = start.elapsed();
                    let verified_data = VerifiedData {
                        challenge_hash: read_hash_from_file(&self.challenge_hash_filename)?,
                        response_hash: read_hash_from_file(&self.response_hash_filename)?,
                        new_challenge_hash: read_hash_from_file(&self.new_challenge_hash_filename)?,
                        verification_duration: Some(duration.as_millis() as u64),
                    };

                    (
                        &self.new_challenge_filename,
                        serde_json::to_value(verified_data)?,
                    )
                }
            };

            self.wait_and_move_chunk_id_from_lane_to_lane(
                &PipelineLane::Process,
                &PipelineLane::Upload,
                &chunk_id,
            )
            .await?;
            let upload_url = self.get_upload_url(&chunk_id).await?;
            let authorization = get_authorization_value(
                &self.private_key,
                "POST",
                &(Url::parse(&upload_url)?.path())[1..],
            )?;

            match self.upload_mode {
                UploadMode::Auto => {
                    if upload_url.contains("blob.core.windows.net") {
                        upload_file_to_azure_async(file_to_upload, &upload_url).await?
                    } else {
                        upload_file_direct_async(&authorization, file_to_upload, &upload_url)
                            .await?
                    }
                }
                UploadMode::Azure => {
                    upload_file_to_azure_async(file_to_upload, &upload_url).await?
                }
                UploadMode::Direct => {
                    upload_file_direct_async(&authorization, file_to_upload, &upload_url).await?
                }
            }
            let signed_data = SignedData {
                signature: sign_json(&self.private_key, &contributed_or_verified_data)?,
                data: contributed_or_verified_data,
            };

            self.notify_contribution(&chunk_id, serde_json::to_value(signed_data)?)
                .await?;

            self.remove_chunk_id_from_lane_if_exists(&PipelineLane::Upload, &chunk_id)?;
        }
    }

    fn get_participant_locked_chunks_display(&self, ceremony: &FilteredChunks) -> Result<Vec<String>> {
        let mut chunk_ids = vec![];
        let pipeline = self.get_pipeline_snapshot()?;
        for lane in &[
            PipelineLane::Download,
            PipelineLane::Process,
            PipelineLane::Upload,
        ] {
            for chunk_id in pipeline
                .get(lane)
                .ok_or(ContributeError::LaneWasNullError(lane.to_string()))?
            {
                if let Some(chunk) = ceremony
                    .chunks
                    .iter()
                    .find(|c| c.chunk_id == chunk_id.clone())
                {
                    if chunk.lock_holder.is_some()
                        && chunk.lock_holder != Some(self.participant_id.clone())
                    {
                        return Err(
                            ContributeError::CouldNotFindChunkWithIDLockedByParticipantError(
                                chunk_id.clone(),
                                self.participant_id.clone(),
                            )
                            .into(),
                        );
                    }
                } else {
                    return Err(
                        ContributeError::CouldNotFindChunkWithIDLockedByParticipantError(
                            chunk_id.clone(),
                            self.participant_id.clone(),
                        )
                        .into(),
                    );
                }

                chunk_ids.push(format!("{} ({})", chunk_id.clone(), lane));
            }
        }
        Ok(chunk_ids)
    }

    async fn release_locked_chunks(&self, ceremony: &Ceremony) -> Result<()> {
        let chunk_ids = ceremony
            .chunks
            .iter()
            .filter(|c| c.lock_holder == Some(self.participant_id.clone()))
            .map(|c| c.chunk_id.clone());
        for chunk_id in chunk_ids {
            self.unlock_chunk(&chunk_id).await?;
        }
        Ok(())
    }

    fn get_non_contributed_chunks(
        &self,
        ceremony: &FilteredChunks,
    ) -> Result<Vec<String>> {
        let mut non_contributed = vec![];

        for chunk in ceremony.chunks.iter() {
            if !chunk.contributed {
                non_contributed.push(chunk.chunk_id.clone());
            }
        }

        Ok(non_contributed)
    }

    fn get_non_contributed_and_available_chunks(
        &self,
        ceremony: &FilteredChunks,
    ) -> Result<Vec<String>> {
        let mut non_contributed = vec![];

        for chunk in ceremony.chunks.iter() {
            if !chunk.contributed && chunk.lock_holder.is_none() {
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

    fn get_download_url_of_last_challenge_for_verifying(&self, chunk: &Chunk) -> Result<String> {
        let url = chunk
            .contributions
            .iter()
            .rev()
            .skip(1)
            .rev()
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

    fn get_download_url_of_last_response(&self, chunk: &Chunk) -> Result<String> {
        let url = chunk
            .contributions
            .iter()
            .last()
            .ok_or(ContributeError::ContributionListWasEmptyForChunkID(
                chunk.chunk_id.to_string(),
            ))?
            .contributed_location
            .clone()
            .ok_or(ContributeError::VerifiedLocationWasNoneForChunkID(
                chunk.chunk_id.to_string(),
            ))?;
        Ok(url)
    }

    async fn get_chunk(&self, chunk_id: &str) -> Result<(usize, Chunk)> {
        let get_path = format!("chunks/{}", chunk_id);
        let get_chunk_url = self.server_url.join(&get_path)?;
        let client = reqwest::Client::new();
        let response = client
            .get(get_chunk_url.as_str())
            .send()
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let chunk: Chunk = serde_json::from_str::<Response<Chunk>>(&data)?.result;
        Ok((chunk_id.parse::<usize>()?, chunk))
    }

    async fn get_ceremony(&self) -> Result<Ceremony> {
        let ceremony_url = self.server_url.join("ceremony")?;
        let client = reqwest::Client::builder().gzip(true).build()?;
        let response = client
            .get(ceremony_url.as_str())
            .send()
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
        Ok(ceremony)
    }

    async fn get_chunk_info(&self) -> Result<FilteredChunks> {
        let get_path = match self.participation_mode {
            ParticipationMode::Contribute => format!("contributor-chunks/{}", self.participant_id),
            ParticipationMode::Verify => format!("verifier-chunks/{}", self.participant_id),
        };
        let ceremony_url = self.server_url.join(&get_path)?;
        let client = reqwest::Client::builder().gzip(true).build()?;
        let response = client
            .get(ceremony_url.as_str())
            .send()
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: FilteredChunks = serde_json::from_str::<Response<FilteredChunks>>(&data)?.result;
        Ok(ceremony)
    }

    async fn lock_chunk(&self, chunk_id: &str) -> Result<()> {
        let lock_path = format!("chunks/{}/lock", chunk_id);
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

    async fn unlock_chunk(&self, chunk_id: &str) -> Result<()> {
        let unlock_path = format!("chunks/{}/unlock", chunk_id);
        let unlock_chunk_url = self.server_url.join(&unlock_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &unlock_path)?;
        client
            .post(unlock_chunk_url.as_str())
            .header(AUTHORIZATION, authorization)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn get_upload_url(&self, chunk_id: &str) -> Result<String> {
        let upload_request_path = format!("chunks/{}/contribution", chunk_id);
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
        info!("Write URL {}", response.result.write_url);
        Ok(response.result.write_url)
    }

    async fn notify_contribution(&self, chunk_id: &str, body: serde_json::Value) -> Result<()> {
        let notify_path = format!("chunks/{}/contribution", chunk_id);
        let notify_url = self.server_url.join(&notify_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &notify_path)?;
        client
            .post(notify_url.as_str())
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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(non_blocking)
        .init();

    let opts: ContributeOpts = ContributeOpts::parse_args_default_or_exit();
    let (seed, private_key) =
        read_keys(&opts.keys_path).expect("Should have loaded Plumo setup keys");

    *SEED.write().expect("Should have been able to write seed") = Some(seed);

    let contribute = Contribute::new(&opts, private_key.expose_secret())
        .expect("Should have been able to create a contribute.");
    match contribute.run_and_catch_errors::<BW6_761>().await {
        Err(e) => panic!("Got error from contribute: {}", e.to_string()),
        _ => {}
    }
}
