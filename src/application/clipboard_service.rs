use crate::{
    domain::UserId,
    infrastructure::object_store::{storage_path_for_hash, StoredObject},
};
use chrono::NaiveDateTime;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};

#[derive(Clone, Debug)]
pub struct CreateTextInput {
    pub content_type: String,
    pub filename: Option<String>,
    pub text_content: String,
}

#[derive(Clone, Debug)]
pub struct CreateObjectInput {
    pub content_type: String,
    pub filename: Option<String>,
    pub object: StoredObject,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct ClipboardItem {
    pub id: i64,
    pub owner_id: UserId,
    pub content_type: String,
    pub filename: Option<String>,
    pub text_content: Option<String>,
    pub object_hash: Option<String>,
    pub mime_type: Option<String>,
    pub content_hash: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Clone, Debug)]
pub struct LocalObject {
    pub byte_size: i64,
    pub storage_path: String,
}

#[derive(Debug)]
pub enum ClipboardServiceError {
    Validation(String),
    NotFound,
    Database(sqlx::Error),
}

pub async fn create_text_current(
    db: &Pool<Postgres>,
    user_id: UserId,
    input: CreateTextInput,
) -> Result<ClipboardItem, ClipboardServiceError> {
    validate_text_input(&input)?;

    let item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        INSERT INTO clipboard_items (owner_id, content_type, filename, text_content)
        VALUES ($1, $2, $3, $4)
        RETURNING id, owner_id, content_type, filename, text_content, object_hash,
                  NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, created_at
        "#,
    )
    .bind(user_id)
    .bind(&input.content_type)
    .bind(input.filename.as_deref())
    .bind(&input.text_content)
    .fetch_one(db)
    .await?;

    Ok(decorate_item(item))
}

pub async fn create_object_current(
    db: &Pool<Postgres>,
    user_id: UserId,
    input: CreateObjectInput,
) -> Result<ClipboardItem, ClipboardServiceError> {
    validate_object_input(&input)?;
    let mut tx = db.begin().await?;

    upsert_object_in_tx(&mut tx, &input.object.hash, input.object.byte_size).await?;

    let item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        INSERT INTO clipboard_items (owner_id, content_type, filename, object_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id, owner_id, content_type, filename, text_content, object_hash,
                  NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, created_at
        "#,
    )
    .bind(user_id)
    .bind(&input.content_type)
    .bind(input.filename.as_deref())
    .bind(&input.object.hash)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(decorate_item(item))
}

pub async fn get_current(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Option<ClipboardItem>, ClipboardServiceError> {
    let item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        SELECT id, owner_id, content_type, filename, text_content, object_hash,
               NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, created_at
        FROM clipboard_items
        WHERE owner_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;

    Ok(item.map(decorate_item))
}

pub async fn history(
    db: &Pool<Postgres>,
    user_id: UserId,
    limit: Option<i64>,
    cursor: Option<i64>,
) -> Result<Vec<ClipboardItem>, ClipboardServiceError> {
    let items = if let Some(limit) = limit {
        sqlx::query_as::<_, ClipboardItem>(
            r#"
            SELECT id, owner_id, content_type, filename, text_content, object_hash,
                   NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, created_at
            FROM clipboard_items
            WHERE owner_id = $1
              AND ($2::BIGINT IS NULL OR id < $2)
            ORDER BY id DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(cursor)
        .bind(limit.clamp(1, 100))
        .fetch_all(db)
        .await?
    } else {
        sqlx::query_as::<_, ClipboardItem>(
            r#"
            SELECT id, owner_id, content_type, filename, text_content, object_hash,
                   NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, created_at
            FROM clipboard_items
            WHERE owner_id = $1
              AND ($2::BIGINT IS NULL OR id < $2)
            ORDER BY id DESC
            "#,
        )
        .bind(user_id)
        .bind(cursor)
        .fetch_all(db)
        .await?
    };

    Ok(items.into_iter().map(decorate_item).collect())
}

pub async fn get_item(
    db: &Pool<Postgres>,
    user_id: UserId,
    item_id: i64,
) -> Result<ClipboardItem, ClipboardServiceError> {
    let item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        SELECT ci.id, ci.owner_id, ci.content_type, ci.filename, ci.text_content, ci.object_hash,
               NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, ci.created_at
        FROM clipboard_items ci
        WHERE ci.id = $1
          AND (
              ci.owner_id = $2 OR EXISTS (
                  SELECT 1 FROM shares s
                  WHERE s.item_id = ci.id
                    AND s.target_user_id = $2
                    AND s.status = 'accepted'
              )
          )
        "#,
    )
    .bind(item_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or(ClipboardServiceError::NotFound)?;

    Ok(decorate_item(item))
}

pub async fn delete_item(
    db: &Pool<Postgres>,
    user_id: UserId,
    item_id: i64,
) -> Result<(), ClipboardServiceError> {
    let result = sqlx::query(
        r#"
        DELETE FROM clipboard_items
        WHERE id = $1 AND owner_id = $2
        "#,
    )
    .bind(item_id)
    .bind(user_id)
    .execute(db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ClipboardServiceError::NotFound);
    }

    Ok(())
}

pub async fn get_content_object(
    db: &Pool<Postgres>,
    user_id: UserId,
    item_id: i64,
    _thumbnail: bool,
) -> Result<(ClipboardItem, Option<LocalObject>), ClipboardServiceError> {
    let item = get_item(db, user_id, item_id).await?;
    let Some(hash) = item.object_hash.as_deref() else {
        return Ok((item, None));
    };

    let byte_size = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT byte_size
        FROM objects
        WHERE hash = $1
        "#,
    )
    .bind(hash)
    .fetch_optional(db)
    .await?
    .ok_or(ClipboardServiceError::NotFound)?;

    let object = LocalObject {
        byte_size,
        storage_path: storage_path_for_hash(hash),
    };

    Ok((item, Some(object)))
}

async fn upsert_object_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    hash: &str,
    byte_size: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO objects (hash, byte_size)
        VALUES ($1, $2)
        ON CONFLICT (hash) DO NOTHING
        "#,
    )
    .bind(hash)
    .bind(byte_size)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

fn validate_text_input(input: &CreateTextInput) -> Result<(), ClipboardServiceError> {
    if !matches!(input.content_type.as_str(), "text" | "file_list") {
        return Err(ClipboardServiceError::Validation(
            "JSON clipboard content_type must be text or file_list".to_string(),
        ));
    }
    if input.text_content.is_empty() {
        return Err(ClipboardServiceError::Validation(
            "text_content cannot be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_object_input(input: &CreateObjectInput) -> Result<(), ClipboardServiceError> {
    if !matches!(input.content_type.as_str(), "image" | "file" | "binary") {
        return Err(ClipboardServiceError::Validation(
            "upload content_type must be image, file, or binary".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn decorate_item(mut item: ClipboardItem) -> ClipboardItem {
    if let Some(text) = item.text_content.as_deref() {
        item.content_hash = Some(sha256_hex(text.as_bytes()));
        if matches!(item.content_type.as_str(), "text" | "file_list") {
            item.mime_type = Some("text/plain; charset=utf-8".to_string());
        }
    } else if let Some(hash) = item.object_hash.as_deref() {
        item.content_hash = Some(hash.to_string());
    }
    item
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

impl From<sqlx::Error> for ClipboardServiceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
