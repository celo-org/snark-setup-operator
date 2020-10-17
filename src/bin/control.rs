use snark_setup_operator::{
    data_structs::{Ceremony, Response},
    error::ControlError,
};

use anyhow::Result;
use ethers::types::PrivateKey;
use gumdrop::Options;
use reqwest::header::AUTHORIZATION;
use snark_setup_operator::utils::get_authorization_value;
use std::{fs::File, io::Write, process, str::FromStr};
use tracing::info;
use url::Url;

#[derive(Debug, Options, Clone)]
pub struct AddParticipantOpts {
    #[options(help = "participant ID", required)]
    pub participant_id: String,
}

#[derive(Debug, Options, Clone)]
pub struct RemoveParticipantOpts {
    #[options(help = "participant ID", required)]
    pub participant_id: String,
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "adds a participant")]
    AddParticipant(AddParticipantOpts),
    RemoveParticipant(RemoveParticipantOpts),
}

#[derive(Debug, Options, Clone)]
pub struct ControlOpts {
    #[options(
        help = "the url of the coordinator API",
        default = "http://localhost:8080"
    )]
    pub coordinator_url: String,
    #[options(help = "the private key of the control", required)]
    pub private_key: String,
    #[options(command, required)]
    pub command: Option<Command>,
}

pub struct Control {
    pub server_url: Url,
    pub private_key: PrivateKey,
}

impl Control {
    pub fn new(opts: &ControlOpts) -> Result<Self> {
        let control = Self {
            server_url: Url::parse(&opts.coordinator_url)?.join("ceremony")?,
            private_key: PrivateKey::from_str(&opts.private_key)?,
        };
        Ok(control)
    }

    async fn add_participant(&self, participant_id: String) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        if ceremony
            .contributor_ids
            .contains(&participant_id.to_string())
        {
            return Err(ControlError::ParticipantAlreadyExistsError(
                participant_id.clone(),
                ceremony.contributor_ids.clone(),
            )
            .into());
        }
        ceremony.contributor_ids.push(participant_id.clone());
        info!("participants after adding: {:?}", ceremony.contributor_ids);
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }

    async fn get_ceremony(&self) -> Result<Ceremony> {
        let response = reqwest::get(self.server_url.as_str())
            .await?
            .error_for_status()?;
        let data = response.text().await?;
        let ceremony: Ceremony = serde_json::from_str::<Response<Ceremony>>(&data)?.result;
        Ok(ceremony)
    }

    fn backup_ceremony(&self, ceremony: &Ceremony) -> Result<()> {
        let filename = format!("ceremony_{}", chrono::Utc::now().timestamp_nanos());
        let mut file = File::create(filename)?;
        file.write_all(serde_json::to_string_pretty(ceremony)?.as_bytes())?;

        Ok(())
    }

    async fn put_ceremony(&self, ceremony: &Ceremony) -> Result<()> {
        self.backup_ceremony(ceremony)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "PUT", "/ceremony")?;
        client
            .put(self.server_url.as_str())
            .header(AUTHORIZATION, authorization)
            .json(ceremony)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn remove_participant(&self, participant_id: String) -> Result<()> {
        let mut ceremony = self.get_ceremony().await?;
        if !ceremony
            .contributor_ids
            .contains(&participant_id.to_string())
        {
            return Err(ControlError::ParticipantDoesNotExistError(
                participant_id.clone(),
                ceremony.contributor_ids.clone(),
            )
            .into());
        }
        ceremony.contributor_ids.retain(|x| *x != participant_id);
        for (chunk_index, chunk) in ceremony.chunks.iter_mut().enumerate() {
            // If the participant is currently holding the lock, release it and continue.
            if chunk.lock_holder == Some(participant_id.to_string()) {
                info!(
                    "chunk {} is locked by the participant, releasing it",
                    chunk_index
                );
                chunk.lock_holder = None;
                continue;
            }
            // Otherwise, check if they contributed in the past and clean it up.
            let mut contribution_index = None;
            for (index, contribution) in chunk.contributions.iter().enumerate() {
                // The first contribution is always the result of initialization, so no need to process it.
                if index == 0 {
                    continue;
                }
                if contribution.contributor_id()? == participant_id {
                    contribution_index = Some(index);
                    break;
                }
            }
            if let Some(contribution_index) = contribution_index {
                info!("chunk {} has a contribution from the participant at index {}, deleting it and its descendants", chunk_index, contribution_index);
                chunk.lock_holder = None;
                chunk.contributions.drain(contribution_index..);
            }
        }
        self.put_ceremony(&ceremony).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opts: ControlOpts = ControlOpts::parse_args_default_or_exit();
    let control = Control::new(&opts).expect("Should have been able to create a control.");
    let command = opts.clone().command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", ControlOpts::usage());
        process::exit(2)
    });

    (match command {
        Command::AddParticipant(opts) => control
            .add_participant(opts.participant_id)
            .await
            .expect("Should have run command successfully"),
        Command::RemoveParticipant(opts) => control
            .remove_participant(opts.participant_id)
            .await
            .expect("Should have run command successfully"),
    });
}
