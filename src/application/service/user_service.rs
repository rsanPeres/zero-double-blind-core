use crate::domain::entity::user_entity::{Role, User};
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use crate::infrastructure::interface::user_repository::UserRepository;
use bcrypt::{hash, DEFAULT_COST};
use std::sync::Arc;

#[derive(Clone)]
pub struct UserService {
    repo: Arc<dyn UserRepository>,
}

impl UserService {
    pub fn new(repo: Arc<dyn UserRepository>) -> Self {
        Self { repo }
    }


    pub async fn get_logged_user(&self, user_id: &str) -> Result<Option<User>, AppError> {
        self.repo.find_by_id(user_id).await
    }

    pub async fn get_user_by_id(&self, id: &str, logged_user: &Option<User>) -> Result<Option<User>, AppError> {
        let user = ensure_user_present(logged_user)?;
        if !user
            .roles
            .iter()
            .any(|r| matches!(r, Role::Admin | Role::ResearcherOwner))
        {
            return Err(AppError::AuthError);
        }
        self.repo.find_by_id(id).await
    }

    pub async fn get_user_by_email(&self, email: &str, logged_user: &Option<User>) -> Result<Option<User>, AppError> {
        let user = ensure_user_present(logged_user)?;
        if !user
            .roles
            .iter()
            .any(|r| matches!(r, Role::Admin | Role::ResearcherOwner))
        {
            return Err(AppError::AuthError);
        }
        self.repo.find_by_email(email).await
    }

    pub async fn update_password(
        &self,
        new_password: &str,
        logged_user: &Option<User>,
    ) -> Result<(), AppError> {
        let user = ensure_user_present(logged_user)?;
        let id = user
            .id
            .as_ref()
            .ok_or_else(|| DomainError::Validation("ID do usuário ausente".into()))?;

        let hashed = hash(new_password, DEFAULT_COST)
            .map_err(|_| DomainError::Validation("Falha ao gerar hash".into()))?;

        self.repo.update_password(&id, &hashed).await
    }


    pub async fn delete_user(&self, id: &str, logged_user: &Option<User>) -> Result<(), AppError> {
        let user = ensure_user_present(logged_user)?;
        if !user.roles.iter().any(|r| matches!(r, Role::Admin)) {
            return Err(AppError::AuthError);
        }
        self.repo.delete(id).await
    }


}

fn ensure_user_present(logged_user: &Option<User>) -> Result<&User, AppError> {
    logged_user
        .as_ref()
        .ok_or_else(|| DomainError::NotFound.into())
}