use crate::domain::entity::user_entity::Claims;
use crate::infrastructure::error::error_handler::AppError;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::env;
use warp::{reject, Filter, Rejection};

pub fn with_auth() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::header::<String>("authorization")
        .and_then(|auth_header: String| async move {
            if !auth_header.to_lowercase().starts_with("bearer ") {
                return Err(reject::custom(AppError::AuthError));
            }
            let token = auth_header[7..].to_string();
            decode::<Claims>(
                &token,
                &DecodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_bytes()),
                &Validation::default(),
            )
                .map(|data| data.claims)
                .map_err(|_| reject::custom(AppError::AuthError))
        })
}