mod api;
mod app_state;
mod application;
mod domain;
mod infrastructure;

use crate::app_state::AppState;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use dotenvy::dotenv;
use serde::Serialize;
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let pool = infrastructure::database::connect_pool().await;
    let app_state = Arc::new(AppState::new(pool));

    let app = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api::router())
        .layer(DefaultBodyLimit::max(max_upload_bytes()))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let addr = env::var("BIND_ADDR")
        .ok()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3000)));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind server address");

    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await.expect("Server failed");
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _database_pool_is_closed = state.db.is_closed();

    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

fn max_upload_bytes() -> usize {
    env::var("MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100 * 1024 * 1024)
}
