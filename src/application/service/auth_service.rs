use crate::domain::entity::user_entity::User;
use crate::infrastructure::error::error_handler::AppError;
use crate::infrastructure::security::jwt_util::create_jwt;
use crate::repository::auth_mongo_repository::AuthMongoRepository;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthService {
    repo: AuthMongoRepository,
}

impl AuthService {
    pub fn new(repo: AuthMongoRepository) -> Self {
        AuthService { repo }
    }

    pub async fn register(&self, mut user: User) -> Result<String, AppError> {
        user.id = Some(Uuid::new_v4().to_string());
        let id = self.repo.register(user).await?;
        Ok(id)
    }

    pub async fn login(&self, email: String, password: String) -> Result<String, String> {
        if let Some(user) = self.repo.find_by_email(&email).await.map_err(|e| e.to_string())? {
            if user.password == password {
                Ok(create_jwt(&user.id.unwrap().to_string(), user.roles))
            } else {
                Err("Invalid password".into())
            }
        } else {
            Err("User not found".into())
        }
    }
}