use crate::domain::entity::auditable_entity::Auditable;
use crate::domain::entity::question_entity::Question;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Answer {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub type_: String,
    pub question: Question,
    pub value: String,
    pub auditable: Option<Auditable>
}