use crate::domain::entity::participant_data_entity::ParticipantData;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParticipantProfile{
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub age: u8,
    pub gender: String,
    pub education_level: String,
    pub income: String,
    pub region: String,
    pub group: Option<String>,
    pub content: String,
    pub data: ParticipantData
}