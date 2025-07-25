use serde::Deserialize;
use crate::domain::entity::user_entity::Role;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub roles: Vec<Role>,
}