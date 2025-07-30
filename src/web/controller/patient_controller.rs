use crate::application::service::patient_service::PatientService;
use crate::web::controller::response::randomization_response::RandomizationResponse;
use std::sync::Arc;
use warp::{http::StatusCode, Rejection, Reply};
use crate::domain::entity::patient_entity::Patient;
use crate::domain::entity::user_entity::User;

#[derive(Clone)]
pub struct PatientController {
    pub patient_service: PatientService,
}

impl PatientController {
    pub fn new(patient_service: PatientService) -> Self {
        Self { patient_service }
    }

    pub async fn register(
        &self,
        patient: Patient,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self
            .patient_service
            .register(patient, &logged_user)
            .await
        {
            Ok(id) => {
                let json = warp::reply::json(&serde_json::json!({ "id": id }));
                Ok(warp::reply::with_status(json, StatusCode::CREATED))
            }
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn find_by_name(
        &self,
        name: String,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self
            .patient_service
            .find_by_name(&name, &logged_user)
            .await
        {
            Ok(list) => Ok(warp::reply::with_status(
                warp::reply::json(&list),
                StatusCode::OK,
            )),
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn find_all(
        &self,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self.patient_service.find_all(&logged_user).await {
            Ok(list) => Ok(warp::reply::with_status(
                warp::reply::json(&list),
                StatusCode::OK,
            )),
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn find_all_ids(
        &self,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self.patient_service.find_all_ids(&logged_user).await {
            Ok(ids) => Ok(warp::reply::with_status(
                warp::reply::json(&ids),
                StatusCode::OK,
            )),
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn update(
        &self,
        id: String,
        patient: Patient,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self
            .patient_service
            .update(&id, patient, &logged_user)
            .await
        {
            Ok(()) => {
                let json = warp::reply::json(&serde_json::json!({ "status": "updated" }));
                Ok(warp::reply::with_status(json, StatusCode::OK))
            }
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn randomize_patients(
        self: Arc<Self>,
        logged_user: Option<User>,
    ) -> Result<impl Reply, Rejection> {
        match self
            .patient_service
            .patient_randomization(&logged_user)
            .await
        {
            Ok(result) => {

                let json = warp::reply::json(&result);
                Ok(warp::reply::with_status(json, StatusCode::OK))
            }
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn delete(
        &self,
        id: String,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self.patient_service.delete(&id, &logged_user).await {
            Ok(()) => {
                let json = warp::reply::json(&serde_json::json!({ "status": "deleted" }));
                Ok(warp::reply::with_status(json, StatusCode::OK))
            }
            Err(e) => Err(warp::reject::custom(e)),
        }
    }
}