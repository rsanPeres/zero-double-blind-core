use crate::domain::entity::answer_entity::Answer;
use crate::domain::entity::auditable_entity::Auditable;
use crate::domain::entity::patient_entity::Patient;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Form {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub answers: Vec<Answer>,
    pub patient: Patient,
    pub comment: String,
    pub auditable: Option<Auditable>
}