use crate::application::service::user_service::UserService;
use crate::web::controller::patient_controller::PatientController;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use crate::domain::entity::patient_entity::Patient;
use crate::domain::entity::user_entity::Claims;
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use crate::infrastructure::security::auth_util::with_auth;

pub fn patient_route(
    controller: Arc<PatientController>,
    user_service: UserService,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let ctrl = {
        let c = controller.clone();
        warp::any().map(move || c.clone()).boxed()
    };
    let svc = {
        let s = user_service.clone();
        warp::any().map(move || s.clone()).boxed()
    };
    let auth = with_auth().boxed();

    let register = warp::path!("patient")
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::json::<Patient>())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |claims: Claims, patient: Patient, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.register(patient, Some(user)).await
            }
        )
        .boxed();

    let by_name = warp::path!("patient" / "name" / String)
        .and(warp::get())
        .and(auth.clone())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |name: String, claims: Claims, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.find_by_name(name, Some(user)).await
            }
        )
        .boxed();

    let get_all = warp::path!("patients")
        .and(warp::get())
        .and(auth.clone())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |claims: Claims, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.find_all(Some(user)).await
            }
        )
        .boxed();

    let get_ids = warp::path!("patients" / "ids")
        .and(warp::get())
        .and(auth.clone())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |claims: Claims, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.find_all_ids(Some(user)).await
            }
        )
        .boxed();

    let randomize = warp::path!("patient" / "randomize" / "off-chain")
        .and(warp::post())
        .and(auth.clone())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |claims: Claims, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.off_chain_randomize_patients(Some(user)).await
            }
        )
        .boxed();

    let randomize_on_chain = warp::path!("patient" / "randomize" / "on-chain")
        .and(warp::post())
        .and(auth.clone())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |claims: Claims, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.on_chain_randomize_patients(Some(user)).await
            }
        )
        .boxed();

    let update = warp::path!("patient" / String)
        .and(warp::put())
        .and(auth.clone())
        .and(warp::body::json::<Patient>())
        .and(svc.clone())
        .and(ctrl.clone())
        .and_then(
            |id: String, claims: Claims, patient: Patient, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.update(id, patient, Some(user)).await
            }
        )
        .boxed();

    let delete = warp::path!("patient" / String)
        .and(warp::delete())
        .and(auth)
        .and(svc)
        .and(ctrl)
        .and_then(
            |id: String, claims: Claims, svc: UserService, ctrl: Arc<PatientController>| async move {
                let user = svc.get_logged_user(&claims.sub)
                    .await
                    .map_err(warp::reject::custom)?
                    .ok_or_else(|| warp::reject::custom(AppError::Domain(DomainError::NotFound)))?;
                ctrl.delete(id, Some(user)).await
            }
        )
        .boxed();

    register
        .or(by_name)
        .or(get_all)
        .or(get_ids)
        .or(randomize)
        .or(randomize_on_chain)
        .or(update)
        .or(delete)
}