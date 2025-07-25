use warp::{Rejection, Reply, http::StatusCode};
use crate::application::service::auth_service::AuthService;
use crate::domain::entity::user_entity::User;
use crate::web::controller::request::user_request::{LoginRequest, RegisterRequest};

#[derive(Clone)]
pub struct AuthController {
    pub auth_service: AuthService,
}

impl AuthController {
    pub fn new(auth_service: AuthService) -> Self {
        Self { auth_service }
    }
    pub async fn register(
        &self,
        body: RegisterRequest,
    ) -> Result<impl Reply + 'static + use<>, Rejection> {
        let mut user = User::new(body);

        match self.auth_service.register(user).await {
            Ok(id) => {
                let json = warp::reply::json(&serde_json::json!({ "id": id }));
                Ok(warp::reply::with_status(json, StatusCode::CREATED))
            }
            Err(e) => {
                let json = warp::reply::json(&serde_json::json!({ "error": e.to_string() }));
                Ok(warp::reply::with_status(json, StatusCode::BAD_REQUEST))
            }
        }
    }

    pub async fn login(&self, body: LoginRequest) -> Result<impl Reply + use<>, Rejection> {
        match self.auth_service.login(body.email, body.password).await {
            Ok(token) => {
                let json = warp::reply::json(&serde_json::json!({ "token": token }));
                Ok(warp::reply::with_status(json, StatusCode::OK))
            }
            Err(e) => {
                let json = warp::reply::json(&serde_json::json!({ "error": e }));
                Ok(warp::reply::with_status(json, StatusCode::UNAUTHORIZED))
            }
        }
    }
}