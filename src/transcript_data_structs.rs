use crate::data_structs::Ceremony;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Transcript {
    pub rounds: Vec<Ceremony>,
    pub beacon_hash: Option<String>,
    pub final_hash: Option<String>,
}
