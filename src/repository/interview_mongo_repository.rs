use async_trait::async_trait;
use futures::stream::TryStreamExt;
use mongodb::{
    bson::doc,
    Collection,
    Cursor,
};
use crate::domain::entity::interview_entity::Interview;
use crate::infrastructure::error::error_handler::AppError;
use crate::infrastructure::interface::interview_repository::InterviewRepository;

#[derive(Clone)]
pub struct InterviewMongoRepository {
    collection: Collection<Interview>,
}

impl InterviewMongoRepository {
    pub fn new(collection: Collection<Interview>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl InterviewRepository for InterviewMongoRepository {
    async fn register(&self, mut interview: Interview) -> Result<String, AppError> {
        let insert_result = self
            .collection
            .insert_one(interview, None)
            .await
            .map_err(AppError::from)?;

        Ok(insert_result.inserted_id.to_string())
    }

    async fn find_by_researcher(&self, researcher_id: &str) -> Result<Vec<Interview>, AppError> {
        let filter = doc! { "researcher_id": researcher_id };
        let mut cursor: Cursor<Interview> = self
            .collection
            .find(filter, None)
            .await
            .map_err(AppError::from)?;

        let interviews = cursor
            .try_collect()
            .await
            .map_err(AppError::from)?;

        Ok(interviews)
    }

    async fn list_all(&self) -> Result<Vec<Interview>, AppError> {
        let mut cursor: Cursor<Interview> = self
            .collection
            .find(None, None)
            .await
            .map_err(AppError::from)?;

        let interviews = cursor
            .try_collect()
            .await
            .map_err(AppError::from)?;

        Ok(interviews)
    }
}
