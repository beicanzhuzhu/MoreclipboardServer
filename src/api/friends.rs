use crate::{
    api::response::ApiError,
    app_state::{AppEvent, AppState},
    application::friend_service::{self, FriendServiceError, FriendSummary, FriendshipDetail},
    domain::AuthenticatedUser,
};
use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/friends", get(list).post(create))
        .route("/friends/incoming", get(incoming))
        .route("/friends/outgoing", get(outgoing))
        .route("/friends/:friendship_id/accept", post(accept))
        .route("/friends/:friendship_id/reject", post(reject))
}

#[derive(Deserialize)]
struct CreateFriendRequest {
    target_user_id: i64,
    message: Option<String>,
}

#[derive(Serialize)]
struct FriendResponse {
    friendship: FriendshipDetail,
}

#[derive(Serialize)]
struct FriendListResponse {
    friends: Vec<FriendSummary>,
}

#[derive(Serialize)]
struct FriendRequestListResponse {
    friendships: Vec<FriendshipDetail>,
}

async fn create(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<CreateFriendRequest>,
) -> Result<Json<FriendResponse>, ApiError> {
    let friendship = friend_service::create_request(
        &state.db,
        user.user_id,
        payload.target_user_id,
        payload.message,
    )
    .await
    .map_err(ApiError::from)?;

    state.notify(
        friendship.friendship.addressee_id,
        AppEvent::FriendRequestReceived {
            friendship_id: friendship.friendship.id,
            requester_id: friendship.friendship.requester_id,
            message: friendship.friendship.message.clone(),
            created_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(FriendResponse { friendship }))
}

async fn list(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<FriendListResponse>, ApiError> {
    let friends = friend_service::friends(&state.db, user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(FriendListResponse { friends }))
}

async fn incoming(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<FriendRequestListResponse>, ApiError> {
    let friendships = friend_service::incoming(&state.db, user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(FriendRequestListResponse { friendships }))
}

async fn outgoing(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<FriendRequestListResponse>, ApiError> {
    let friendships = friend_service::outgoing(&state.db, user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(FriendRequestListResponse { friendships }))
}

async fn accept(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(friendship_id): Path<i64>,
) -> Result<Json<FriendResponse>, ApiError> {
    let friendship = friend_service::accept(&state.db, user.user_id, friendship_id)
        .await
        .map_err(ApiError::from)?;

    state.notify(
        friendship.friendship.requester_id,
        AppEvent::FriendshipResponded {
            friendship_id: friendship.friendship.id,
            addressee_id: user.user_id,
            status: friendship.friendship.status.clone(),
            responded_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(FriendResponse { friendship }))
}

async fn reject(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(friendship_id): Path<i64>,
) -> Result<Json<FriendResponse>, ApiError> {
    let friendship = friend_service::reject(&state.db, user.user_id, friendship_id)
        .await
        .map_err(ApiError::from)?;

    state.notify(
        friendship.friendship.requester_id,
        AppEvent::FriendshipResponded {
            friendship_id: friendship.friendship.id,
            addressee_id: user.user_id,
            status: friendship.friendship.status.clone(),
            responded_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(FriendResponse { friendship }))
}

impl From<FriendServiceError> for ApiError {
    fn from(error: FriendServiceError) -> Self {
        match error {
            FriendServiceError::Validation(message) => ApiError::bad_request(message),
            FriendServiceError::NotFound => ApiError::not_found("friend request not found"),
            FriendServiceError::Conflict => ApiError::conflict("friend request already exists"),
            FriendServiceError::Database(error) => {
                tracing::error!(?error, "friend database operation failed");
                ApiError::internal("friend operation failed")
            }
        }
    }
}
