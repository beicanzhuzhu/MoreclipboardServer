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
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub summary: Option<String>,
    pub text_content: String,
    pub source_device_id: String,
}

#[derive(Clone, Debug)]
pub struct CreateObjectInput {
    pub content_type: String,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub summary: Option<String>,
    pub source_device_id: String,
    pub object: StoredObject,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct ClipboardItem {
    pub id: i64,
    pub owner_id: UserId,
    pub content_type: String,
    pub mime_type: Option<String>,
    pub filename: Option<String>,
    pub summary: Option<String>,
    pub text_content: Option<String>,
    pub object_hash: Option<String>,
    pub thumbnail_hash: Option<String>,
    pub content_hash: Option<String>,
    pub source_device_id: Option<String>,
    pub created_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct LocalObject {
    pub byte_size: i64,
    pub mime_type: Option<String>,
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
    let content_hash = sha256_hex(input.text_content.as_bytes());
    let mut tx = db.begin().await?;

    let item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        INSERT INTO clipboard_items (
            owner_id, content_type, mime_type, filename, summary,
            text_content, content_hash, source_device_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, owner_id, content_type, mime_type, filename, summary,
                  text_content, object_hash, thumbnail_hash, content_hash,
                  source_device_id, created_at, deleted_at
        "#,
    )
    .bind(user_id)
    .bind(&input.content_type)
    .bind(input.mime_type.as_deref())
    .bind(input.filename.as_deref())
    .bind(input.summary.as_deref())
    .bind(&input.text_content)
    .bind(content_hash)
    .bind(&input.source_device_id)
    .fetch_one(&mut *tx)
    .await?;

    set_current_in_tx(&mut tx, user_id, item.id).await?;
    tx.commit().await?;
    Ok(item)
}

pub async fn create_object_current(
    db: &Pool<Postgres>,
    user_id: UserId,
    input: CreateObjectInput,
) -> Result<ClipboardItem, ClipboardServiceError> {
    validate_object_input(&input)?;
    let mut tx = db.begin().await?;

    upsert_local_object_in_tx(
        &mut tx,
        &input.object.hash,
        input.object.byte_size,
        input.mime_type.as_deref(),
    )
    .await?;

    let item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        INSERT INTO clipboard_items (
            owner_id, content_type, mime_type, filename, summary,
            object_hash, content_hash, source_device_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
        RETURNING id, owner_id, content_type, mime_type, filename, summary,
                  text_content, object_hash, thumbnail_hash, content_hash,
                  source_device_id, created_at, deleted_at
        "#,
    )
    .bind(user_id)
    .bind(&input.content_type)
    .bind(input.mime_type.as_deref())
    .bind(input.filename.as_deref())
    .bind(input.summary.as_deref())
    .bind(&input.object.hash)
    .bind(&input.source_device_id)
    .fetch_one(&mut *tx)
    .await?;

    set_current_in_tx(&mut tx, user_id, item.id).await?;
    tx.commit().await?;
    Ok(item)
}

pub async fn get_current(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Option<ClipboardItem>, ClipboardServiceError> {
    sqlx::query_as::<_, ClipboardItem>(
        r#"
        SELECT ci.id, ci.owner_id, ci.content_type, ci.mime_type, ci.filename, ci.summary,
               ci.text_content, ci.object_hash, ci.thumbnail_hash, ci.content_hash,
               ci.source_device_id, ci.created_at, ci.deleted_at
        FROM current_clipboards cc
        JOIN clipboard_items ci ON ci.id = cc.clipboard_item_id
        WHERE cc.user_id = $1 AND ci.deleted_at IS NULL
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(ClipboardServiceError::from)
}

pub async fn history(
    db: &Pool<Postgres>,
    user_id: UserId,
    limit: i64,
    cursor: Option<i64>,
) -> Result<Vec<ClipboardItem>, ClipboardServiceError> {
    let limit = limit.clamp(1, 100);

    sqlx::query_as::<_, ClipboardItem>(
        r#"
        SELECT id, owner_id, content_type, mime_type, filename, summary,
               text_content, object_hash, thumbnail_hash, content_hash,
               source_device_id, created_at, deleted_at
        FROM clipboard_items
        WHERE owner_id = $1
          AND deleted_at IS NULL
          AND ($2::BIGINT IS NULL OR id < $2)
        ORDER BY id DESC
        LIMIT $3
        "#,
    )
    .bind(user_id)
    .bind(cursor)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(ClipboardServiceError::from)
}

pub async fn get_item(
    db: &Pool<Postgres>,
    user_id: UserId,
    item_id: i64,
) -> Result<ClipboardItem, ClipboardServiceError> {
    sqlx::query_as::<_, ClipboardItem>(
        r#"
        SELECT ci.id, ci.owner_id, ci.content_type, ci.mime_type, ci.filename, ci.summary,
               ci.text_content, ci.object_hash, ci.thumbnail_hash, ci.content_hash,
               ci.source_device_id, ci.created_at, ci.deleted_at
        FROM clipboard_items ci
        WHERE ci.id = $1
          AND ci.deleted_at IS NULL
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
    .ok_or(ClipboardServiceError::NotFound)
}

pub async fn delete_item(
    db: &Pool<Postgres>,
    user_id: UserId,
    item_id: i64,
) -> Result<(), ClipboardServiceError> {
    let mut tx = db.begin().await?;

    let result = sqlx::query(
        r#"
        UPDATE clipboard_items
        SET deleted_at = NOW()
        WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(item_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ClipboardServiceError::NotFound);
    }

    sqlx::query(
        r#"
        DELETE FROM current_clipboards
        WHERE user_id = $1 AND clipboard_item_id = $2
        "#,
    )
    .bind(user_id)
    .bind(item_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn get_content_object(
    db: &Pool<Postgres>,
    user_id: UserId,
    item_id: i64,
    thumbnail: bool,
) -> Result<(ClipboardItem, Option<LocalObject>), ClipboardServiceError> {
    let item = get_item(db, user_id, item_id).await?;
    let hash = if thumbnail && item.content_type == "image" {
        item.thumbnail_hash
            .as_deref()
            .or(item.object_hash.as_deref())
    } else if thumbnail {
        item.thumbnail_hash.as_deref()
    } else {
        item.object_hash.as_deref()
    };

    let Some(hash) = hash else {
        return Ok((item, None));
    };

    let object = sqlx::query_as::<_, LocalObject>(
        r#"
        SELECT byte_size, mime_type, storage_path
        FROM local_objects
        WHERE hash = $1
        "#,
    )
    .bind(hash)
    .fetch_optional(db)
    .await?
    .ok_or(ClipboardServiceError::NotFound)?;

    sqlx::query("UPDATE local_objects SET last_accessed_at = NOW() WHERE hash = $1")
        .bind(hash)
        .execute(db)
        .await?;

    Ok((item, Some(object)))
}

async fn set_current_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    user_id: UserId,
    item_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO current_clipboards (user_id, clipboard_item_id, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (user_id) DO UPDATE
        SET clipboard_item_id = EXCLUDED.clipboard_item_id,
            updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(item_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn upsert_local_object_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    hash: &str,
    byte_size: i64,
    mime_type: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO local_objects (hash, byte_size, mime_type)
        VALUES ($1, $2, $3)
        ON CONFLICT (hash) DO UPDATE
        SET last_accessed_at = NOW()
        "#,
    )
    .bind(hash)
    .bind(byte_size)
    .bind(mime_type)
    .execute(&mut **tx)
    .await?;

    debug_assert_eq!(
        storage_path_for_hash(hash).len(),
        "objects/ab/cd/".len() + 60
    );
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
    if !matches!(
        input.content_type.as_str(),
        "text" | "image" | "file" | "binary"
    ) {
        return Err(ClipboardServiceError::Validation(
            "upload content_type must be text, image, file, or binary".to_string(),
        ));
    }
    Ok(())
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
