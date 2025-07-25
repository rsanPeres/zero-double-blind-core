use crate::web::controller::auth_controller::AuthController;
use crate::web::controller::request::user_request::{LoginRequest, RegisterRequest};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

pub fn auth_route(
    controller: Arc<AuthController>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let ctrl = warp::any().map(move || controller.clone()).boxed();

    let register = warp::path!( "auth" / "register")
        .and(warp::post())
        .and(warp::body::json::<RegisterRequest>())
        .and(ctrl.clone())
        .and_then(
            |body: RegisterRequest, ctrl: Arc<AuthController>| async move {
                ctrl.register(body).await
            }
        ).boxed();

    let login = warp::path!("auth" / "login")
        .and(warp::post())
        .and(warp::body::json::<LoginRequest>())
        .and(ctrl)
        .and_then(
            |body: LoginRequest, ctrl: Arc<AuthController>| async move {
                ctrl.login(body).await
            }
        ).boxed();

    register.or(login)
}