use crate::{
    api::response::ApiError,
    app_state::AppState,
    application::user_service,
    domain::{AuthenticatedUser, UserProfile},
};
use axum::{
    extract::{Extension, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/users/search", get(search))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Serialize)]
struct SearchResponse {
    users: Vec<UserProfile>,
}

async fn search(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    let users = user_service::search_users(&state.db, user.user_id, &query.q)
        .await
        .map_err(|error| {
            tracing::error!(?error, "user search database operation failed");
            ApiError::internal("user search failed")
        })?;

    Ok(Json(SearchResponse { users }))
}
