use crate::application::service::randomization_service::{RandomizationError, RandomizationService};
use crate::domain::entity::patient_entity::Patient;
use crate::domain::entity::user_entity::{Role, User};
use crate::infrastructure::error::error_handler::{AppError, DomainError, InfrastructureError};
use crate::infrastructure::interface::patient_repository::PatientRepository;
use std::sync::Arc;
use ark_r1cs_std::boolean::Boolean;

#[derive(Clone)]
pub struct PatientService {
    repo: Arc<dyn PatientRepository>,
    rand_svc: RandomizationService,
}

impl PatientService {
    pub fn new(repo: Arc<dyn PatientRepository>, pk_path: impl AsRef<std::path::Path>, vk_path: impl AsRef<std::path::Path>) -> Result<Self, AppError> {
        let rand_svc = RandomizationService::new(pk_path.as_ref(), vk_path.as_ref())
            .map_err(|e| AppError::Infra(InfrastructureError::DataError))?;
        Ok(Self { repo, rand_svc })
    }

    pub async fn register(
        &self,
        patient: Patient,
        logged_user: &Option<User>,
    ) -> Result<String, AppError> {
        let user = ensure_user_present(logged_user)?;
        let is_admin_or_owner = user
            .roles
            .iter()
            .any(|r| matches!(r, Role::Admin | Role::ResearcherOwner));
        if !is_admin_or_owner {
            return Err(AppError::AuthError);
        }
        self.repo.register(patient).await
    }

    pub async fn find_by_name(
        &self,
        name: &str,
        logged_user: &Option<User>,
    ) -> Result<Vec<Patient>, AppError> {
        ensure_user_present(logged_user)?;
        self.repo.find_by_name(name).await
    }

    pub async fn find_all(
        &self,
        logged_user: &Option<User>,
    ) -> Result<Vec<Patient>, AppError> {
        let user = ensure_user_present(logged_user)?;
        let allowed = user
            .roles
            .iter()
            .any(|r| matches!(r, Role::Admin | Role::ResearcherOwner));
        if !allowed {
            return Err(AppError::AuthError);
        }
        self.repo.find_all().await
    }

    pub async fn find_all_ids(
        &self,
        logged_user: &Option<User>,
    ) -> Result<Vec<String>, AppError> {
        let user = ensure_user_present(logged_user)?;
        let allowed = user
            .roles
            .iter()
            .any(|r| matches!(r, Role::Admin | Role::BlindingAdmin));
        if !allowed {
            return Err(AppError::AuthError);
        }
        self.repo.find_all_ids().await
    }

    pub async fn patient_randomization(
        &self,
        logged_user: &Option<User>,
    ) -> Result<bool, AppError> {
        // 1) Ensure user present
        let user = logged_user
            .as_ref()
            .ok_or_else(|| DomainError::NotFound)?;

        // 2) Check BlindingAdmin role
        if !user.roles.iter().any(|r| matches!(r, Role::BlindingAdmin)) {
            return Err(AppError::AuthError);
        }

        // 3) Fetch all patient IDs
        let ids = self.repo.find_all_ids().await?;

        // 4) Run the Groth16 randomization + proof
        let (assignments, proof_bytes, public_inputs_bytes) =
            self.rand_svc
                .randomize_patients(ids)
                .map_err(|e| match e {
                    RandomizationError::SerializationError   => AppError::Infra(InfrastructureError::DataError),
                    RandomizationError::ProofGenerationError => AppError::Infra(InfrastructureError::Crypto(bcrypt::BcryptError::InvalidCost("Proof Generation error".to_string()))),
                })?;

        let result = self.rand_svc.verify_randomization_proof(&proof_bytes, &public_inputs_bytes)
            .map_err(|e| AppError::Infra(InfrastructureError::CryptoError))?;

        Ok(result)
    }

    pub async fn update(
        &self,
        id: &str,
        patient: Patient,
        logged_user: &Option<User>,
    ) -> Result<(), AppError> {
        let user = ensure_user_present(logged_user)?;
        if !user.roles.iter().any(|r| matches!(r, Role::Admin)) {
            return Err(AppError::AuthError);
        }
        self.repo.update(id, patient).await
    }

    pub async fn delete(
        &self,
        id: &str,
        logged_user: &Option<User>,
    ) -> Result<(), AppError> {
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