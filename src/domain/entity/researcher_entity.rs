use serde::{Deserialize, Serialize};
use crate::domain::entity::participant_data_entity::ParticipantData;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Researcher {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub data: ParticipantData
}