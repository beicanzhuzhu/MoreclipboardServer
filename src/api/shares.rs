use crate::{api::response::not_implemented, app_state::AppState};
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/shares",
            post(|| async { not_implemented("POST /api/v1/shares") }),
        )
        .route(
            "/shares/incoming",
            get(|| async { not_implemented("GET /api/v1/shares/incoming") }),
        )
        .route(
            "/shares/outgoing",
            get(|| async { not_implemented("GET /api/v1/shares/outgoing") }),
        )
        .route(
            "/shares/:share_id/accept",
            post(|| async { not_implemented("POST /api/v1/shares/{share_id}/accept") }),
        )
        .route(
            "/shares/:share_id/reject",
            post(|| async { not_implemented("POST /api/v1/shares/{share_id}/reject") }),
        )
}
