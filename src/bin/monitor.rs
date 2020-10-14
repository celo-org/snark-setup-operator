#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("Metadata was none")]
    MetadataNoneError,
    #[error("Lock time was none")]
    LockTimeIsNoneError,
    #[error("Lock holder was none")]
    LockHolderIsNoneError,
}

use snark_setup_operator::data_structs::{Ceremony, Response};

use anyhow::Result;
use chrono::Duration;
use gumdrop::Options;
use std::collections::HashSet;
use thiserror::Error;
use tracing::info;
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct MonitorOpts {
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(help = "timeout in minutes", default = "1")]
    pub timeout: i64,
}

pub struct Monitor {
    pub server_url: Url,
    pub timeout: Duration,
}

impl Monitor {
    pub fn new(opts: &MonitorOpts) -> Result<Self> {
        let monitor = Self {
            server_url: Url::parse(&opts.coordinator_url)?.join("ceremony")?,
            timeout: Duration::minutes(opts.timeout),
        };
        Ok(monitor)
    }

    async fn run(&self) -> Result<()> {
        let data = reqwest::get(self.server_url.as_str()).await?.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;

        self.check_timeout(&ceremony)?;
        self.check_all_done(&ceremony)?;
        self.show_finished_chunks(&ceremony)?;

        Ok(())
    }

    fn check_timeout(&self, ceremony: &Ceremony) -> Result<()> {
        let current_time = chrono::Utc::now();
        let mut timed_out_participant_ids = vec![];
        for chunk in ceremony.chunks.iter() {
            let participant_id = match chunk.lock_holder.as_ref() {
                Some(participant_id) => participant_id.clone(),
                None => continue,
            };

            let lock_time = chunk
                .metadata
                .as_ref()
                .ok_or(MonitorError::MetadataNoneError)?
                .lock_holder_time
                .ok_or(MonitorError::LockTimeIsNoneError)?;
            let elapsed = current_time - lock_time;
            if elapsed > self.timeout {
                timed_out_participant_ids.push(participant_id);
            }
        }
        info!("timed out participants: {:?}", timed_out_participant_ids);

        Ok(())
    }

    fn check_all_done(&self, ceremony: &Ceremony) -> Result<()> {
        let participant_ids: HashSet<_> = ceremony.contributor_ids.iter().clone().collect();

        if ceremony.chunks.iter().all(|chunk| {
            let verified_participant_ids_in_chunk: HashSet<_> = chunk
                .contributions
                .iter()
                .filter(|c| c.verified)
                .map(|c| c.contributor_id.as_ref())
                .filter_map(|e| e)
                .collect();
            participant_ids
                .iter()
                .all(|p| verified_participant_ids_in_chunk.contains(*p))
        }) {
            info!("all done");
        }

        Ok(())
    }

    fn show_finished_chunks(&self, ceremony: &Ceremony) -> Result<()> {
        let participant_ids: HashSet<_> = ceremony.contributor_ids.iter().clone().collect();

        let mut chunks_complete = vec![];
        let mut chunks_incomplete = vec![];

        for chunk in ceremony.chunks.iter() {
            let verified_participant_ids_in_chunk: HashSet<_> = chunk
                .contributions
                .iter()
                .filter(|c| c.verified)
                .map(|c| c.contributor_id.as_ref())
                .filter_map(|e| e)
                .collect();
            if participant_ids
                .iter()
                .all(|p| verified_participant_ids_in_chunk.contains(*p))
            {
                chunks_complete.push(chunk.chunk_id.clone())
            } else {
                chunks_incomplete.push(chunk.chunk_id.clone())
            }
        }

        info!("complete chunks: {:?}", chunks_complete);
        info!("incomplete chunks: {:?}", chunks_incomplete);

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opts: MonitorOpts = MonitorOpts::parse_args_default_or_exit();

    let monitor = Monitor::new(&opts).expect("Should have been able to create a monitor.");
    let mut monitor_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        monitor_interval.tick().await;

        match monitor.run().await {
            Err(e) => info!("Got error from monitor: {}", e.to_string()),
            _ => {}
        }
    }
}
