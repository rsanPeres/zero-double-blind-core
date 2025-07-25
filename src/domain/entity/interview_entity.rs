use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::domain::entity::auditable_entity::Auditable;
use crate::domain::entity::form_entity::Form;
use crate::domain::entity::interview_stage_entity::InterviewSage;
use crate::domain::entity::interview_status_entity::InterviewStatus;
use crate::domain::entity::researcher_entity::Researcher;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Interview {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub form: Form,
    pub stage: InterviewSage,
    pub date_time: DateTime<Utc>,
    pub researcher: Researcher,
    pub collaborators: Vec<Researcher>,
    pub auditable: Option<Auditable>,
    pub status: InterviewStatus,
}