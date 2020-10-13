#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("Metadata was none")]
    MetadataNoneError,
    #[error("Lock time was none")]
    LockTimeIsNoneError,
    #[error("Lock holder was none")]
    LockHolderIsNoneError,
}

use snark_setup_operator::{
    data_structs::{Ceremony, Response},
    metrics::start_metrics,
};

use anyhow::Result;
use chrono::Duration;
use gumdrop::Options;
use thiserror::Error;
use tokio::time::delay_for;
use tracing::info;
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct MonitorOpts {
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(help = "listen url for metrics", default = "127.0.0.1")]
    pub listen_url: String,
    #[options(help = "listen port for metrics", default = "10101")]
    pub listen_port: u16,
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opts: MonitorOpts = MonitorOpts::parse_args_default_or_exit();

    let monitor = Monitor::new(&opts).expect("Should have been able to create a monitor.");
    tokio::spawn(async move {
        loop {
            delay_for(
                Duration::seconds(5)
                    .to_std()
                    .expect("Should have converted to standard duration"),
            )
            .await;
            match monitor.run().await {
                Err(e) => info!("Got error: {}", e.to_string()),
                _ => {}
            }
        }
    });

    start_metrics(&opts.listen_url, opts.listen_port)
        .await
        .expect("Should have been able to wait for metrics.");
}
