use crate::{api::response::not_implemented, app_state::AppState};
use axum::{routing::get, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route(
        "/events",
        get(|| async { not_implemented("GET /api/v1/events") }),
    )
}
