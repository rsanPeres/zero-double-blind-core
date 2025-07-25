use crate::domain::entity::user_entity::User;
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use mongodb::bson::doc;
use mongodb::Collection;

#[derive(Clone)]
pub struct AuthMongoRepository {
    collection: Collection<User>,
}

impl AuthMongoRepository {
    pub fn new(collection: Collection<User>) -> Self {
        Self { collection }
    }
    pub async fn register(&self, user: User) -> Result<String, AppError> {
        if let Some(_) = self.find_by_email(&user.email).await? {
            return Err(DomainError::Validation("E-mail já cadastrado".into()).into());
        }

        let saved = self.collection
            .insert_one(&user, None)
            .await
            .map_err(AppError::from)?;

        Ok(saved.inserted_id.to_string())
    }

    pub async fn find_by_email(&self, email: &str) -> mongodb::error::Result<Option<User>> {
        self.collection.find_one(doc! { "email": email }, None).await
    }
}