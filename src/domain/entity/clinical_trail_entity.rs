use serde::{Deserialize, Serialize};
use crate::domain::entity::auditable_entity::Auditable;
use crate::domain::entity::clinical_trial_status_entity::ClinicalTrialStatus;
use crate::domain::entity::researcher_entity::Researcher;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClinicalTrial {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub title: String,
    pub number_participants: usize,
    pub research: String,
    pub owner: Researcher,
    pub collaborators: Vec<Researcher>,
    pub auditable: Option<Auditable>,
    pub status: ClinicalTrialStatus
}