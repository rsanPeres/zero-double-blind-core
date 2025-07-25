use serde::{Deserialize, Serialize};
use crate::domain::entity::participant_profile_entity::ParticipantProfile;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Patient {
    #[serde(
        rename = "_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<String>,
    pub group: String,
    pub phase: String,
    pub blinded_group: bool,
    pub profile: ParticipantProfile
}