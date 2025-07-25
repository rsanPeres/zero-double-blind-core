use serde::{Deserialize, Serialize};
use crate::domain::entity::auditable_entity::Auditable;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Question {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub title: String,
    pub auditable: Option<Auditable>
}