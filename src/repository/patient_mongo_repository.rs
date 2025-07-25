use async_trait::async_trait;
use futures::stream::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId},
    Collection,
    Cursor,
};
use uuid::Uuid;
use crate::domain::entity::patient_entity::Patient;
use crate::infrastructure::error::error_handler::AppError;
use crate::infrastructure::error::error_handler::DomainError::Validation;
use crate::infrastructure::interface::patient_repository::PatientRepository;

#[derive(Clone)]
pub struct PatientMongoRepository {
    collection: Collection<Patient>,
}

impl PatientMongoRepository {
    pub fn new(collection: Collection<Patient>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl PatientRepository for PatientMongoRepository {
    async fn register(&self, mut patient: Patient) -> Result<String, AppError> {
        // garante que não há id pré-existente
        patient.id = Option::from(Uuid::new_v4().to_string());
        let insert = self
            .collection
            .insert_one(patient, None)
            .await
            .map_err(AppError::from)?;
        Ok(insert.inserted_id.to_string())
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<Patient>, AppError> {
        let filter = doc! { "profile.data.first_name": name };
        let mut cursor: Cursor<Patient> = self
            .collection
            .find(filter, None)
            .await
            .map_err(AppError::from)?;
        let patients = cursor.try_collect().await.map_err(AppError::from)?;
        Ok(patients)
    }

    async fn find_all(&self) -> Result<Vec<Patient>, AppError> {
        let mut cursor: Cursor<Patient> = self
            .collection
            .find(None, None)
            .await
            .map_err(AppError::from)?;
        let patients = cursor.try_collect().await.map_err(AppError::from)?;
        Ok(patients)
    }

    async fn find_all_ids(&self) -> Result<Vec<String>, AppError> {
        let patients = self.find_all().await?;
        let ids = patients
            .into_iter()
            .filter_map(|patient| patient.id)
            .collect::<Vec<String>>();
        Ok(ids)
    }

    async fn update(&self, id: &str, mut patient: Patient) -> Result<(), AppError> {
        // converte para ObjectId
        let obj_id = ObjectId::parse_str(id)
            .map_err(|_| AppError::Domain(Validation("ID inválido".into())))?;
        patient.id = Some(id.to_string());
        self.collection
            .replace_one(doc! { "_id": obj_id }, patient, None)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<(), AppError> {
        let obj_id = ObjectId::parse_str(id)
            .map_err(|_| AppError::Domain(Validation("ID inválido".into())))?;
        self.collection
            .delete_one(doc! { "_id": obj_id }, None)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }
}