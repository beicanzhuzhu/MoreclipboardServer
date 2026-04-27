use crate::{api::response::not_implemented, app_state::AppState};
use axum::{response::Response, routing::get, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/users/search", get(search))
}

async fn search() -> Response {
    not_implemented("GET /api/v1/users/search")
}
