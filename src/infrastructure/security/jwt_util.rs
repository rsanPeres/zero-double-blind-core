use crate::domain::entity::user_entity::{Claims, Role};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::env;

pub fn create_jwt(user_id: &str, roles: Vec<Role>) -> String {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(360))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string().to_owned(),
        exp: expiration,
        roles,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_bytes()),
    )
        .expect("Failed to create token")
}