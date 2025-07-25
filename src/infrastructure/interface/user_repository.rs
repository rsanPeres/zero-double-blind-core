use async_trait::async_trait;
use crate::domain::entity::user_entity::User;
use crate::infrastructure::error::error_handler::AppError;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn find_by_id(&self, id: &str) -> Result<Option<User>, AppError>;
    async fn find_all(&self) -> Result<Vec<User>, AppError>;
    async fn update_password(&self, id: &str, hash: &str) -> Result<(), AppError>;
    async fn delete(&self, id: &str) -> Result<(), AppError>;
}