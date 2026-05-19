use crate::{
    api::response::ApiError,
    app_state::AppState,
    application::auth_service::{self, AuthServiceError, LoginInput, RegisterInput, Session},
    domain::{AuthenticatedUser, UserProfile},
    infrastructure::jwt,
};
use axum::{
    extract::{Extension, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub fn public_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
}

pub fn protected_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/logout", post(logout))
        .route("/me", get(me))
}

pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, ApiError> {
    let token = bearer_token(req.headers())?;
    let claims = jwt::decode_access_token(token)
        .map_err(|_| ApiError::unauthorized("invalid or expired access token"))?;

    req.extensions_mut().insert(AuthenticatedUser {
        user_id: claims.sub,
        device_id: claims.device_id,
    });

    Ok(next.run(req).await)
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    device_id: Option<String>,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
struct LogoutRequest {
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct AuthResponse {
    token_type: &'static str,
    access_token: String,
    refresh_token: String,
    expires_in: usize,
    user: UserProfile,
}

#[derive(Serialize)]
struct MeResponse {
    user: UserProfile,
    device_id: String,
}

#[derive(Serialize)]
struct MessageResponse {
    message: &'static str,
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth_service::register(
        &state.db,
        RegisterInput {
            username: payload.username,
            password: payload.password,
        },
    )
    .await
    .map_err(ApiError::from)?;

    Ok((StatusCode::CREATED, Json(user)))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let session = auth_service::login(
        &state.db,
        LoginInput {
            username: payload.username,
            password: payload.password,
            device_id: payload.device_id,
        },
    )
    .await
    .map_err(ApiError::from)?;

    Ok(Json(AuthResponse::from(session)))
}

async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let session = auth_service::refresh_session(&state.db, &payload.refresh_token)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(AuthResponse::from(session)))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    payload: Option<Json<LogoutRequest>>,
) -> Result<Json<MessageResponse>, ApiError> {
    let refresh_token = payload
        .as_ref()
        .and_then(|Json(payload)| payload.refresh_token.as_deref());

    auth_service::logout(&state.db, user.user_id, &user.device_id, refresh_token)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(MessageResponse {
        message: "logged out",
    }))
}

async fn me(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> Result<Json<MeResponse>, ApiError> {
    let user = auth_service::get_user_profile(&state.db, auth_user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(MeResponse {
        user,
        device_id: auth_user.device_id,
    }))
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("invalid authorization header"))?;

    auth.strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("authorization header must use bearer token"))
}

impl From<Session> for AuthResponse {
    fn from(session: Session) -> Self {
        Self {
            token_type: "Bearer",
            access_token: session.access_token,
            refresh_token: session.refresh_token,
            expires_in: session.expires_in,
            user: session.user,
        }
    }
}

impl From<AuthServiceError> for ApiError {
    fn from(error: AuthServiceError) -> Self {
        match error {
            AuthServiceError::Validation(message) => ApiError::bad_request(message),
            AuthServiceError::UsernameTaken => ApiError::conflict("username already exists"),
            AuthServiceError::InvalidCredentials => {
                ApiError::unauthorized("invalid username or password")
            }
            AuthServiceError::InvalidToken => ApiError::unauthorized("invalid or expired token"),
            AuthServiceError::NotFound => ApiError::not_found("user not found"),
            AuthServiceError::HashFailed | AuthServiceError::TokenFailed => {
                ApiError::internal("authentication failed")
            }
            AuthServiceError::Database(error) => {
                tracing::error!(?error, "authentication database operation failed");
                ApiError::internal("authentication failed")
            }
        }
    }
}
