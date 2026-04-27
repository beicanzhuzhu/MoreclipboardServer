use crate::{api::response::not_implemented, app_state::AppState};
use axum::{
    response::Response,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/me", get(me))
}

async fn register() -> Response {
    not_implemented("POST /api/v1/auth/register")
}

async fn login() -> Response {
    not_implemented("POST /api/v1/auth/login")
}

async fn refresh() -> Response {
    not_implemented("POST /api/v1/auth/refresh")
}

async fn logout() -> Response {
    not_implemented("POST /api/v1/auth/logout")
}

async fn me() -> Response {
    not_implemented("GET /api/v1/me")
}
