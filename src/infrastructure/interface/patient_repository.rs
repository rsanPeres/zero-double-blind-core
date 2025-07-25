use async_trait::async_trait;
use crate::domain::entity::patient_entity::Patient;
use crate::infrastructure::error::error_handler::AppError;

#[async_trait]
pub trait PatientRepository: Send + Sync {
    async fn register(&self, patient: Patient) -> Result<String, AppError>;
    async fn find_by_name(&self, name: &str) -> Result<Vec<Patient>, AppError>;
    async fn find_all(&self) -> Result<Vec<Patient>, AppError>;
    async fn find_all_ids(&self) -> Result<Vec<String>, AppError>;
    async fn update(&self, id: &str, patient: Patient) -> Result<(), AppError>;
    async fn delete(&self, id: &str) -> Result<(), AppError>;
}