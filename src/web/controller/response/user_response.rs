use serde::{Deserialize, Serialize};
use crate::domain::entity::user_entity::User;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserResponse {
    id: String,
    email: String,
    roles: Vec<String>,
}

impl From<Option<User>> for UserResponse {
    fn from(u: Option<User>) -> Self {
        let user = u.unwrap();
        Self {
            id: user.id.unwrap(),
            email: user.email,
            roles: user.roles.iter().map(|r| format!("{:?}", r)).collect(),
        }
    }
}

#[derive(Deserialize)]
pub struct PasswordUpdate {
    pub new_password: String,
}
