use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiMessage {
    pub code: &'static str,
    pub message: &'static str,
    pub endpoint: &'static str,
}

pub fn not_implemented(endpoint: &'static str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiMessage {
            code: "not_implemented",
            message: "route is registered; business logic is not implemented",
            endpoint,
        }),
    )
        .into_response()
}
