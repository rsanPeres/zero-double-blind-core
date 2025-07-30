use bcrypt::BcryptError;
use mongodb::error::Error as MongoError;
use serde::Serialize;
use std::convert::Infallible;
use bson::de::Error;
use thiserror::Error;
use warp::{http::StatusCode, reject::Reject, Rejection, Reply};

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Entity not found")]
    NotFound,

    #[error("Validation failure: {0}")]
    Validation(String),
}

#[derive(Debug, Error)]
pub enum InfrastructureError {
    #[error("MongoDB error: {0}")]
    Mongo(#[from] MongoError),

    #[error("Cryptography error: {0}")]
    Crypto(#[from] BcryptError),

    #[error("Data error")]
    DataError,

    #[error("ZK error")]
    CryptoError
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Domain error: {0}")]
    Domain(#[from] DomainError),

    #[error("Infrastructure error: {0}")]
    Infra(#[from] InfrastructureError),

    #[error("Invalid or expired JWT token")]
    AuthError,

    #[error("Malformed request: {0}")]
    BadRequest(String),
    #[error("Malformed config: {0}")]
    Config(String),
}

impl Reject for AppError {}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub code: u16,
    pub error: String,
    pub trace: String,
    pub hint: Option<String>,
}

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (status, msg, trace, hint) = if let Some(app_err) = err.find::<AppError>() {
        let trace = format!("{:?}", app_err);
        let code = match app_err {
            AppError::Domain(DomainError::NotFound)      => StatusCode::NOT_FOUND,
            AppError::Domain(DomainError::Validation(_)) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Infra(_)                           => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::AuthError                          => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_)                      => StatusCode::BAD_REQUEST,
            _ => {StatusCode::INTERNAL_SERVER_ERROR}
        };
        (code, app_err.to_string(), trace, None)
    } else if err.is_not_found() {
        let trace = format!("{:?}", err);
        let msg = "Route or resource not found".to_string();
        let hint = Some("Verify that the endpoint and HTTP method are correct".to_string());
        (StatusCode::NOT_FOUND, msg, trace, hint)
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        let trace = format!("{:?}", err);
        let hint = Some("This resource exists but does not accept this HTTP method".to_string());
        (StatusCode::METHOD_NOT_ALLOWED, "HTTP method not allowed".into(), trace, hint)
    } else {
        let trace = format!("{:?}", err);
        eprintln!("Unhandled rejection: {}", trace);
        let hint = Some("Unexpected internal error. Check logs.".to_string());
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into(), trace, hint)
    };

    let json = warp::reply::json(&ErrorResponse {
        code: status.as_u16(),
        error: msg,
        trace,
        hint,
    });
    Ok(warp::reply::with_status(json, status))
}

impl From<MongoError> for AppError {
    fn from(err: MongoError) -> Self {
        AppError::Infra(InfrastructureError::Mongo(err))
    }
}