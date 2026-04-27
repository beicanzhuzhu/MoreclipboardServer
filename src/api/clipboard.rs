use crate::{api::response::not_implemented, app_state::AppState};
use axum::{
    response::Response,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/clipboard/current", get(get_current).post(set_current))
        .route("/clipboard/current/upload", post(upload_current))
        .route("/clipboard/history", get(history))
        .route("/clipboard/history/:item_id", delete(delete_history_item))
        .route("/clipboard/items/:item_id", get(get_item))
        .route("/clipboard/items/:item_id/content", get(get_item_content))
        .route(
            "/clipboard/items/:item_id/thumbnail",
            get(get_item_thumbnail),
        )
}

async fn get_current() -> Response {
    not_implemented("GET /api/v1/clipboard/current")
}

async fn set_current() -> Response {
    not_implemented("POST /api/v1/clipboard/current")
}

async fn upload_current() -> Response {
    not_implemented("POST /api/v1/clipboard/current/upload")
}

async fn history() -> Response {
    not_implemented("GET /api/v1/clipboard/history")
}

async fn delete_history_item() -> Response {
    not_implemented("DELETE /api/v1/clipboard/history/{item_id}")
}

async fn get_item() -> Response {
    not_implemented("GET /api/v1/clipboard/items/{item_id}")
}

async fn get_item_content() -> Response {
    not_implemented("GET /api/v1/clipboard/items/{item_id}/content")
}

async fn get_item_thumbnail() -> Response {
    not_implemented("GET /api/v1/clipboard/items/{item_id}/thumbnail")
}
