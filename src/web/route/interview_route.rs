use crate::application::service::user_service::UserService;
use crate::web::controller::interview_controller::InterviewController;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use crate::domain::entity::interview_entity::Interview;
use crate::domain::entity::user_entity::Claims;
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use crate::infrastructure::security::auth_util::with_auth;

pub fn interview_route(
    controller: Arc<InterviewController>,
    user_service: UserService,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let ctrl = warp::any().map(move || controller.clone()).boxed();
    let svc  = warp::any().map(move || user_service.clone()).boxed();
    let auth = with_auth().boxed();

    let register = warp::path!("interview" / "register")
        .and(warp::post())
        .and(warp::body::json::<Interview>())
        .and(ctrl.clone())
        .and_then(
            |interview: Interview, ctrl: Arc<InterviewController>| async move {
                ctrl.register(interview).await
            }
        ).boxed();

    let find_by_researcher = warp::path!("interview" / "researcher" / String)
        .and(warp::get())
        .and(auth.clone())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |researcher_id: String, claims: Claims, svc: UserService, ctrl: Arc<InterviewController>| async move {
                // 1) obtém o usuário logado do token
                let maybe_user = svc
                    .get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?;
                let user = maybe_user
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.find_by_researcher(researcher_id, Some(user)).await
            }
        ).boxed();

    // GET /api/interviews
    let list_all = warp::path!("api" / "interviews")
        .and(warp::get())
        .and(auth)
        .and(svc)
        .and(ctrl)
        .and_then(
            |claims: Claims, svc: UserService, ctrl: Arc<InterviewController>| async move {
                let maybe_user = svc
                    .get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?;
                let user = maybe_user
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.list_all(Some(user)).await
            }
        ).boxed();

    register
        .or(find_by_researcher)
        .or(list_all)
}