use crate::domain::entity::interview_entity::Interview;
use crate::domain::entity::user_entity::{Role, User};
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use crate::infrastructure::interface::interview_repository::InterviewRepository;
use std::sync::Arc;

#[derive(Clone)]
pub struct InterviewService {
    repo: Arc<dyn InterviewRepository>,
}

impl InterviewService {
    pub fn new(repo: Arc<dyn InterviewRepository>) -> Self {
        Self { repo }
    }

    pub async fn find_by_researcher(
        &self,
        researcher_id: &str,
        logged_user: &Option<User>,
    ) -> Result<Vec<Interview>, AppError> {
        let user = ensure_user_present(logged_user)?;

        let is_admin_or_owner = user.roles.iter().any(|r| {
            matches!(r, Role::Admin | Role::ResearcherOwner)
        });
        let is_self = user.id.as_ref().map(|u| u.to_string()) == Some(researcher_id.to_string());

        if !is_admin_or_owner && !is_self {
            return Err(AppError::AuthError);
        }

        self.repo.find_by_researcher(researcher_id).await
    }

    pub async fn list_all(
        &self,
        logged_user: &Option<User>,
    ) -> Result<Vec<Interview>, AppError> {
        let user = ensure_user_present(logged_user)?;

        if !user.roles.iter().any(|r| matches!(r, Role::Admin | Role::ResearcherOwner)) {
            return Err(AppError::AuthError);
        }

        self.repo.list_all().await
    }

    pub async fn register(&self, interview: Interview) -> Result<String, AppError> {
        self.repo.register(interview).await
    }
}

fn ensure_user_present(logged_user: &Option<User>) -> Result<&User, AppError> {
    logged_user
        .as_ref()
        .ok_or_else(|| DomainError::NotFound.into())
}