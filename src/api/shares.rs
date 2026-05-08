use crate::{
    api::response::ApiError,
    app_state::{AppEvent, AppState},
    application::share_service::{
        self, AcceptedShare, ShareDetail, ShareRecord, ShareServiceError,
    },
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
        .route("/shares", post(create))
        .route("/shares/incoming", get(incoming))
        .route("/shares/outgoing", get(outgoing))
        .route("/shares/:share_id/accept", post(accept))
        .route("/shares/:share_id/reject", post(reject))
}

#[derive(Deserialize)]
struct CreateShareRequest {
    item_id: i64,
    target_user_id: i64,
    message: Option<String>,
}

#[derive(Serialize)]
struct ShareResponse {
    share: ShareRecord,
}

#[derive(Serialize)]
struct ShareListResponse {
    shares: Vec<ShareDetail>,
}

#[derive(Serialize)]
struct AcceptResponse {
    share: AcceptedShare,
}

async fn create(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<CreateShareRequest>,
) -> Result<Json<ShareResponse>, ApiError> {
    let share = share_service::create_share(
        &state.db,
        user.user_id,
        payload.item_id,
        payload.target_user_id,
        payload.message,
    )
    .await
    .map_err(ApiError::from)?;

    state.notify(
        share.target_user_id,
        AppEvent::ShareReceived {
            share_id: share.id,
            item_id: share.item_id,
            from_user_id: share.from_user_id,
            message: share.message.clone(),
            created_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(ShareResponse { share }))
}

async fn incoming(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<ShareListResponse>, ApiError> {
    let shares = share_service::incoming(&state.db, user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(ShareListResponse { shares }))
}

async fn outgoing(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<ShareListResponse>, ApiError> {
    let shares = share_service::outgoing(&state.db, user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(ShareListResponse { shares }))
}

async fn accept(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(share_id): Path<i64>,
) -> Result<Json<AcceptResponse>, ApiError> {
    let accepted = share_service::accept(&state.db, user.user_id, share_id)
        .await
        .map_err(ApiError::from)?;

    state.notify(
        accepted.share.from_user_id,
        AppEvent::ShareResponded {
            share_id: accepted.share.id,
            item_id: accepted.share.item_id,
            target_user_id: user.user_id,
            status: accepted.share.status.clone(),
            responded_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(AcceptResponse { share: accepted }))
}

async fn reject(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(share_id): Path<i64>,
) -> Result<Json<ShareResponse>, ApiError> {
    let share = share_service::reject(&state.db, user.user_id, share_id)
        .await
        .map_err(ApiError::from)?;

    state.notify(
        share.from_user_id,
        AppEvent::ShareResponded {
            share_id: share.id,
            item_id: share.item_id,
            target_user_id: user.user_id,
            status: share.status.clone(),
            responded_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(ShareResponse { share }))
}

impl From<ShareServiceError> for ApiError {
    fn from(error: ShareServiceError) -> Self {
        match error {
            ShareServiceError::Validation(message) => ApiError::bad_request(message),
            ShareServiceError::NotFound => ApiError::not_found("share not found"),
            ShareServiceError::Conflict => ApiError::conflict("share already exists"),
            ShareServiceError::Database(error) => {
                tracing::error!(?error, "share database operation failed");
                ApiError::internal("share operation failed")
            }
        }
    }
}
