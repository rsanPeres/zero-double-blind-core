use warp::{Reply, Rejection, http::StatusCode};
use crate::application::service::user_service::UserService;
use crate::domain::entity::user_entity::User;
use crate::web::controller::response::user_response::{UserResponse, PasswordUpdate};

#[derive(Clone)]
pub struct UserController {
    pub user_service: UserService,
}

impl UserController {
    pub fn new(user_service: UserService) -> Self {
        Self { user_service }
    }

    pub async fn get_user_by_id(
        &self,
        id: String,
        logged_user: Option<User>,
    ) -> Result<impl Reply + 'static, Rejection> {
        self.user_service
            .get_user_by_id(&id, &logged_user)
            .await
            .map(|u| {
                let resp = UserResponse::from(u);
                warp::reply::with_status(warp::reply::json(&resp), StatusCode::OK)
            })
            .map_err(warp::reject::custom)
    }

    pub async fn get_user_by_email(
        &self,
        email: String,
        logged_user: Option<User>,
    ) -> Result<impl Reply + 'static + use<>, Rejection> {
        self.user_service
            .get_user_by_email(&email, &logged_user)
            .await
            .map(|u| {
                let resp = UserResponse::from(u);
                warp::reply::with_status(warp::reply::json(&resp), StatusCode::OK)
            })
            .map_err(warp::reject::custom)
    }

    pub async fn update_password(
        &self,
        body: PasswordUpdate,
        logged_user: Option<User>,
    )-> Result<impl Reply + 'static + use<>, Rejection> {
        self.user_service
            .update_password(&body.new_password, &logged_user)
            .await
            .map(|_| {
                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({ "status": "ok" })),
                    StatusCode::OK,
                )
            })
            .map_err(warp::reject::custom)
    }

    pub async fn delete_user(
        &self,
        id: String,
        logged_user: Option<User>,
    ) -> Result<impl Reply + 'static + use<>, Rejection> {
        self.user_service
            .delete_user(&id, &logged_user)
            .await
            .map(|_| {
                warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({ "status": "deleted" })),
                    StatusCode::OK,
                )
            })
            .map_err(warp::reject::custom)
    }
}