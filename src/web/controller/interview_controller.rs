use warp::{http::StatusCode, Rejection, Reply};

use crate::application::service::interview_service::InterviewService;
use crate::domain::entity::interview_entity::Interview;
use crate::domain::entity::user_entity::User;

#[derive(Clone)]
pub struct InterviewController {
    pub interview_service: InterviewService,
}

impl InterviewController {
    pub fn new(interview_service: InterviewService) -> Self {
        Self { interview_service }
    }

    /// POST /api/interviews
    pub async fn register(
        &self,
        interview: Interview,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self.interview_service.register(interview).await {
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

    pub async fn find_by_researcher(
        &self,
        researcher_id: String,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {
        match self.interview_service.find_by_researcher(&researcher_id, &Some(logged_user.unwrap())).await {
            Ok(list) => Ok(warp::reply::with_status(warp::reply::json(&list), StatusCode::OK)),
            Err(e) => Err(warp::reject::custom(e)),
        }
    }

    pub async fn list_all(
        &self,
        logged_user: Option<User>,
    ) -> Result<impl Reply + use<>, Rejection> {

        match self.interview_service.list_all(&Some(logged_user.unwrap())).await {
            Ok(list) => Ok(warp::reply::with_status(warp::reply::json(&list), StatusCode::OK)),
            Err(e) => Err(warp::reject::custom(e)),
        }
    }
}
