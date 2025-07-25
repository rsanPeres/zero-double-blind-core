use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::domain::entity::auditable_entity::Auditable;
use crate::web::controller::request::user_request::RegisterRequest;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub email: String,

    pub password: String,

    pub roles: Vec<Role>,

    pub login_at: DateTime<Utc>,

    pub auditable: Option<Auditable>
}

impl User {
    pub(crate) fn new(request: RegisterRequest) -> User {
        User{
            id: None,
            email: request.email,
            password: request.password,
            roles: request.roles,
            login_at: Default::default(),
            auditable: None,
        }

    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub roles: Vec<Role>,
}


#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Role {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "researcher")]
    Researcher,
    #[serde(rename = "researcher_owner")]
    ResearcherOwner,
    #[serde(rename = "data_entry")]
    DataEntry,
    #[serde(rename = "blinding_admin")]
    BlindingAdmin,
    #[serde(rename = "patient")]
    Patient,
}