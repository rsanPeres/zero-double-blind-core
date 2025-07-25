use crate::web::controller::response::user_response::PasswordUpdate;
use crate::web::controller::user_controller::UserController;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use crate::domain::entity::user_entity::Claims;
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use crate::infrastructure::security::auth_util::with_auth;

pub fn user_route(
    controller: Arc<UserController>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let ctrl = warp::any().map(move || controller.clone()).boxed();
    let auth = with_auth().boxed();

    // GET /user/email/{email}
    let get_email = warp::path!("user" / "email" / String)
        .and(warp::get())
        .and(auth.clone())
        .and(ctrl.clone())
        .and_then(
            |email: String, claims: Claims, ctrl: Arc<UserController>| async move {
                // 1) pega Result<Option<User>,AppError>
                let maybe_user = ctrl
                    .user_service
                    .get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?;
                // 2) converte Option<User> em User ou rejeita
                let user = maybe_user
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                // 3) passa Some(user) pro controller
                ctrl.get_user_by_email(email, Option::from(user)).await
            }
        ).boxed();

    // PUT /user/{id}/password
    let update_pwd = warp::path!("user" / "password")
        .and(warp::put())
        .and(auth.clone())
        .and(warp::body::json::<PasswordUpdate>())
        .and(ctrl.clone())
        .and_then(
            |claims: Claims, body: PasswordUpdate, ctrl: Arc<UserController>| async move {
                // busca o usuário logado a partir do token
                let maybe_user = ctrl
                    .user_service
                    .get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?;
                let user = maybe_user
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.update_password(body, Some(user)).await
            }
        ).boxed();

    let delete = warp::path!("user" / String)
        .and(warp::delete())
        .and(auth)
        .and(ctrl)
        .and_then(
            |id: String, claims: Claims, ctrl: Arc<UserController>| async move {
                let maybe_user = ctrl
                    .user_service
                    .get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?;
                let user = maybe_user
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.delete_user(id, Option::from(user)).await
            }
        ).boxed();

    get_email
        .or(update_pwd)
        .or(delete)
}