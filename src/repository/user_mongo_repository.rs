use async_trait::async_trait;
use futures::stream::TryStreamExt;
use mongodb::bson::oid::ObjectId;
use mongodb::{bson::doc, Collection, Cursor};
use crate::domain::entity::user_entity::User;
use crate::infrastructure::error::error_handler::{AppError, DomainError};
use crate::infrastructure::interface::user_repository::UserRepository;

#[derive(Clone)]
pub struct UserMongoRepository {
    collection: Collection<User>,
}

impl UserMongoRepository {
    pub fn new(collection: Collection<User>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl UserRepository for UserMongoRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        self.collection.
            find_one(doc! { "email": email }, None)
            .await
            .map_err(AppError::from)
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<User>, AppError> {
        let filter = doc! { "_id": id };
        self.collection
            .find_one(filter, None)
            .await
            .map_err(AppError::from)
    }


    async fn find_all(&self) -> Result<Vec<User>, AppError> {
        let cursor: Cursor<User> = self
            .collection
            .find(None, None)
            .await
            .map_err(AppError::from)?;

        let users: Vec<User> = cursor
            .try_collect()
            .await
            .map_err(AppError::from)?;

        Ok(users)
    }

    async fn update_password(&self, id: &str, new_hash: &str) -> Result<(), AppError> {
        let update = doc! { "$set": { "password_hash": new_hash } };
        self.collection
            .update_one(doc! { "_id": id }, update, None)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<(), AppError> {
        let obj_id = ObjectId::parse_str(id)
            .map_err(|_| DomainError::Validation("ID inválido".into()))?;
        self.collection
            .delete_one(doc! { "_id": obj_id }, None)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }
}
