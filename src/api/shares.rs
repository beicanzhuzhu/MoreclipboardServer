use crate::{api::response::not_implemented, app_state::AppState};
use axum::{
    response::Response,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/shares", post(create))
        .route("/shares/incoming", get(incoming))
        .route("/shares/outgoing", get(outgoing))
        .route("/shares/:share_id/accept", post(accept))
        .route("/shares/:share_id/reject", post(reject))
}

async fn create() -> Response {
    not_implemented("POST /api/v1/shares")
}

async fn incoming() -> Response {
    not_implemented("GET /api/v1/shares/incoming")
}

async fn outgoing() -> Response {
    not_implemented("GET /api/v1/shares/outgoing")
}

async fn accept() -> Response {
    not_implemented("POST /api/v1/shares/{share_id}/accept")
}

async fn reject() -> Response {
    not_implemented("POST /api/v1/shares/{share_id}/reject")
}
