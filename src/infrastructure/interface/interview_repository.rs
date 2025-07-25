use async_trait::async_trait;
use crate::domain::entity::interview_entity::Interview;
use crate::infrastructure::error::error_handler::AppError;

#[async_trait]
pub trait InterviewRepository: Send + Sync {
    async fn register(&self, interview: Interview) -> Result<String, AppError>;
    async fn find_by_researcher(&self, researcher_id: &str) -> Result<Vec<Interview>, AppError>;
    async fn list_all(&self) -> Result<Vec<Interview>, AppError>;
}