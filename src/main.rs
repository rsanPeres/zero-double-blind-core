mod application;
mod domain;
mod infrastructure;
mod repository;
mod web;

use std::env;
use crate::application::service::auth_service::AuthService;
use crate::application::service::interview_service::InterviewService;
use crate::application::service::patient_service::PatientService;
use crate::application::service::randomization_service::RandomizationService;
use crate::application::service::user_service::UserService;
use crate::infrastructure::database::connect_db;
use crate::web::controller::auth_controller::AuthController;
use crate::web::controller::interview_controller::InterviewController;
use crate::web::controller::patient_controller::PatientController;
use crate::web::controller::user_controller::UserController;
use crate::web::route::auth_route::auth_route;
use crate::web::route::interview_route::interview_route;
use crate::web::route::patient_route::patient_route;
use crate::web::route::user_route::user_route;
use dotenvy::dotenv;
use std::sync::Arc;
use warp::Filter;
use crate::domain::entity::user_entity::User;
use crate::infrastructure::interface::interview_repository::InterviewRepository;
use crate::infrastructure::interface::patient_repository::PatientRepository;
use crate::infrastructure::interface::user_repository::UserRepository;
use crate::infrastructure::zk::trusted_setup::generate_pk_vk_to_files;
use crate::repository::auth_mongo_repository::AuthMongoRepository;
use crate::repository::interview_mongo_repository::InterviewMongoRepository;
use crate::repository::patient_mongo_repository::PatientMongoRepository;
use crate::repository::user_mongo_repository::UserMongoRepository;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = connect_db().await?;

    dotenv().ok();

    let auth_repo = AuthMongoRepository::new(db.collection::<User>("user"));

    let mongo_user_repo = UserMongoRepository::new(db.collection::<_>("user"));
    let user_repo: Arc<dyn UserRepository> = Arc::new(mongo_user_repo);

    let mongo_patient_repo = PatientMongoRepository::new(db.collection::<_>("patient"));
    let patient_repo: Arc<dyn PatientRepository> = Arc::new(mongo_patient_repo);

    let mongo_interview_repo = InterviewMongoRepository::new(db.collection::<_>("interview"));
    let interview_repo: Arc<dyn InterviewRepository> = Arc::new(mongo_interview_repo);

    // repos
    let auth_service = AuthService::new(auth_repo);
    let auth_controller = AuthController::new(auth_service);

    let pk_path = "./keys/patient_random.pk";
    let vk_path = "./keys/patient_random.vk";

    generate_pk_vk_to_files(pk_path, vk_path, patient_repo.find_all_ids().await.unwrap())?;
    println!("✅ Trusted setup gerado em `{}` e `{}`", pk_path, vk_path);

    let rand_svc = RandomizationService::new(pk_path, vk_path);
    let patient_service = PatientService::new(
        patient_repo.clone(), pk_path, pk_path).unwrap();
    let patient_controller = Arc::new(PatientController::new(patient_service.clone()));

    let user_service = UserService::new(user_repo);
    let user_controller = UserController::new(user_service.clone());

    let interview_service = InterviewService::new(interview_repo);
    let interview_controller = InterviewController::new(interview_service);

    // routes
    let auth_api = auth_route(Arc::new(auth_controller));
    let user_api = user_route(Arc::new(user_controller));
    let interview_api = interview_route(Arc::new(interview_controller), user_service.clone());
    let patient_api = patient_route(patient_controller, user_service.clone());


    let routes = auth_api
        .or(user_api)
        .or(interview_api)
        .or(patient_api)
        .boxed();

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;


    Ok(())
}
