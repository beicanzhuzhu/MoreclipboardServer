use crate::{
    api::response::ApiError,
    app_state::{AppEvent, AppState},
    application::clipboard_service::{
        self, ClipboardItem, ClipboardServiceError, CreateObjectInput, CreateTextInput,
    },
    domain::AuthenticatedUser,
};
use axum::{
    body::Body,
    extract::{Extension, Multipart, Path, Query, State},
    http::{
        header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_util::io::ReaderStream;

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

#[derive(Deserialize)]
struct SetCurrentRequest {
    content_type: Option<String>,
    mime_type: Option<String>,
    filename: Option<String>,
    summary: Option<String>,
    text_content: String,
}

#[derive(Deserialize)]
struct UploadMetadata {
    content_type: Option<String>,
    mime_type: Option<String>,
    filename: Option<String>,
    summary: Option<String>,
}

#[derive(Deserialize)]
struct HistoryQuery {
    limit: Option<i64>,
    cursor: Option<i64>,
}

#[derive(Serialize)]
struct ItemResponse {
    item: ClipboardItem,
}

#[derive(Serialize)]
struct CurrentResponse {
    item: Option<ClipboardItem>,
}

#[derive(Serialize)]
struct HistoryResponse {
    items: Vec<ClipboardItem>,
    next_cursor: Option<i64>,
}

#[derive(Serialize)]
struct DeleteResponse {
    message: &'static str,
}

async fn get_current(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<CurrentResponse>, ApiError> {
    let item = clipboard_service::get_current(&state.db, user.user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(CurrentResponse { item }))
}

async fn set_current(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<SetCurrentRequest>,
) -> Result<Json<ItemResponse>, ApiError> {
    let item = clipboard_service::create_text_current(
        &state.db,
        user.user_id,
        CreateTextInput {
            content_type: payload.content_type.unwrap_or_else(|| "text".to_string()),
            mime_type: payload.mime_type,
            filename: payload.filename,
            summary: payload.summary,
            text_content: payload.text_content,
            source_device_id: user.device_id.clone(),
        },
    )
    .await
    .map_err(ApiError::from)?;

    notify_clipboard_updated(&state, user.user_id, item.id, &user.device_id);
    Ok(Json(ItemResponse { item }))
}

async fn upload_current(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    mut multipart: Multipart,
) -> Result<Json<ItemResponse>, ApiError> {
    let mut metadata = UploadMetadata {
        content_type: None,
        mime_type: None,
        filename: None,
        summary: None,
    };
    let mut object = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("invalid multipart body"))?
    {
        let name = field.name().unwrap_or_default().to_string();
        if name == "metadata" {
            let bytes = field
                .bytes()
                .await
                .map_err(|_| ApiError::bad_request("invalid metadata field"))?;
            metadata = serde_json::from_slice(&bytes)
                .map_err(|_| ApiError::bad_request("metadata must be valid JSON"))?;
            continue;
        }

        if name == "file" {
            let field_mime_type = field.content_type().map(str::to_string);
            let field_filename = field.file_name().map(str::to_string);
            let mut pending = state
                .object_store
                .begin_write()
                .await
                .map_err(|_| ApiError::internal("failed to start object upload"))?;

            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|_| ApiError::bad_request("failed to read upload chunk"))?
            {
                pending
                    .write_chunk(&chunk)
                    .await
                    .map_err(|_| ApiError::internal("failed to write uploaded object"))?;
            }

            let stored = state
                .object_store
                .finish_write(pending)
                .await
                .map_err(|_| ApiError::internal("failed to finish object upload"))?;

            if metadata.mime_type.is_none() {
                metadata.mime_type = field_mime_type;
            }
            if metadata.filename.is_none() {
                metadata.filename = field_filename;
            }
            object = Some(stored);
        }
    }

    let object = object.ok_or_else(|| ApiError::bad_request("missing multipart file field"))?;
    let content_type = metadata.content_type.unwrap_or_else(|| "file".to_string());

    let item = clipboard_service::create_object_current(
        &state.db,
        user.user_id,
        CreateObjectInput {
            content_type,
            mime_type: metadata.mime_type,
            filename: metadata.filename,
            summary: metadata.summary,
            source_device_id: user.device_id.clone(),
            object,
        },
    )
    .await
    .map_err(ApiError::from)?;

    notify_clipboard_updated(&state, user.user_id, item.id, &user.device_id);
    Ok(Json(ItemResponse { item }))
}

async fn history(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, ApiError> {
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let items = clipboard_service::history(&state.db, user.user_id, limit, query.cursor)
        .await
        .map_err(ApiError::from)?;
    let next_cursor = if items.len() == limit as usize {
        items.last().map(|item| item.id)
    } else {
        None
    };

    Ok(Json(HistoryResponse { items, next_cursor }))
}

async fn delete_history_item(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(item_id): Path<i64>,
) -> Result<Json<DeleteResponse>, ApiError> {
    clipboard_service::delete_item(&state.db, user.user_id, item_id)
        .await
        .map_err(ApiError::from)?;

    state.notify(
        user.user_id,
        AppEvent::ClipboardDeleted {
            item_id,
            source_device_id: user.device_id,
            updated_at: Utc::now().to_rfc3339(),
        },
    );

    Ok(Json(DeleteResponse { message: "deleted" }))
}

async fn get_item(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(item_id): Path<i64>,
) -> Result<Json<ItemResponse>, ApiError> {
    let item = clipboard_service::get_item(&state.db, user.user_id, item_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(ItemResponse { item }))
}

async fn get_item_content(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(item_id): Path<i64>,
) -> Result<Response, ApiError> {
    content_response(state, user.user_id, item_id, false).await
}

async fn get_item_thumbnail(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(item_id): Path<i64>,
) -> Result<Response, ApiError> {
    content_response(state, user.user_id, item_id, true).await
}

async fn content_response(
    state: Arc<AppState>,
    user_id: i64,
    item_id: i64,
    thumbnail: bool,
) -> Result<Response, ApiError> {
    let (item, object) =
        clipboard_service::get_content_object(&state.db, user_id, item_id, thumbnail)
            .await
            .map_err(ApiError::from)?;

    if let Some(object) = object {
        let path = state.object_store.absolute_path(&object.storage_path);
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|_| ApiError::not_found("object file not found"))?;
        let stream = ReaderStream::new(file);
        let body = Body::from_stream(stream);
        let mut headers = HeaderMap::new();

        let mime_type = item
            .mime_type
            .as_deref()
            .or(object.mime_type.as_deref())
            .unwrap_or("application/octet-stream");
        headers.insert(CONTENT_TYPE, header_value(mime_type)?);
        headers.insert(CONTENT_LENGTH, header_value(&object.byte_size.to_string())?);
        if let Some(filename) = item.filename.as_deref() {
            headers.insert(
                CONTENT_DISPOSITION,
                header_value(&format!(
                    "attachment; filename=\"{}\"",
                    sanitize_header(filename)
                ))?,
            );
        }

        return Ok((StatusCode::OK, headers, body).into_response());
    }

    let text = item
        .text_content
        .ok_or_else(|| ApiError::not_found("clipboard content not found"))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        header_value(
            item.mime_type
                .as_deref()
                .unwrap_or("text/plain; charset=utf-8"),
        )?,
    );

    Ok((StatusCode::OK, headers, text).into_response())
}

fn notify_clipboard_updated(state: &AppState, user_id: i64, item_id: i64, source_device_id: &str) {
    state.notify(
        user_id,
        AppEvent::ClipboardUpdated {
            item_id,
            source_device_id: source_device_id.to_string(),
            updated_at: Utc::now().to_rfc3339(),
        },
    );
}

fn header_value(value: &str) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(value).map_err(|_| ApiError::internal("invalid response header"))
}

fn sanitize_header(value: &str) -> String {
    value.replace(['"', '\r', '\n'], "_")
}

impl From<ClipboardServiceError> for ApiError {
    fn from(error: ClipboardServiceError) -> Self {
        match error {
            ClipboardServiceError::Validation(message) => ApiError::bad_request(message),
            ClipboardServiceError::NotFound => ApiError::not_found("clipboard item not found"),
            ClipboardServiceError::Database(error) => {
                tracing::error!(?error, "clipboard database operation failed");
                ApiError::internal("clipboard operation failed")
            }
        }
    }
}
