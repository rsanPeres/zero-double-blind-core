use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use crate::domain::entity::auditable_entity::Auditable;
use crate::domain::entity::user_entity::User;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ParticipantData {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub email: String,
    pub cpf: String,
    pub date_of_birth: NaiveDate,
    pub phone_number: String,
    pub gender: String,
    pub first_name: String,
    pub last_name: String,
    pub nationality: String,
    pub occupation: String,

    pub zipcode: String,
    pub street: String,
    pub city: String,
    pub state: String,
    pub country: String,

    pub auditable: Option<Auditable>,

    pub auth_user: User
}