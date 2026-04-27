use crate::{api::response::not_implemented, app_state::AppState};
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/clipboard/current",
            get(|| async { not_implemented("GET /api/v1/clipboard/current") })
                .post(|| async { not_implemented("POST /api/v1/clipboard/current") }),
        )
        .route(
            "/clipboard/current/upload",
            post(|| async { not_implemented("POST /api/v1/clipboard/current/upload") }),
        )
        .route(
            "/clipboard/history",
            get(|| async { not_implemented("GET /api/v1/clipboard/history") }),
        )
        .route(
            "/clipboard/history/:item_id",
            delete(|| async { not_implemented("DELETE /api/v1/clipboard/history/{item_id}") }),
        )
        .route(
            "/clipboard/items/:item_id",
            get(|| async { not_implemented("GET /api/v1/clipboard/items/{item_id}") }),
        )
        .route(
            "/clipboard/items/:item_id/content",
            get(|| async { not_implemented("GET /api/v1/clipboard/items/{item_id}/content") }),
        )
        .route(
            "/clipboard/items/:item_id/thumbnail",
            get(|| async { not_implemented("GET /api/v1/clipboard/items/{item_id}/thumbnail") }),
        )
}
