use crate::{
    application::{
        clipboard_service::{self, ClipboardItem},
        friend_service,
    },
    domain::{UserId, UserProfile},
};
use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::{Pool, Postgres};

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct ShareRecord {
    pub id: i64,
    pub item_id: i64,
    pub from_user_id: UserId,
    pub target_user_id: UserId,
    pub status: String,
    pub message: Option<String>,
    pub created_at: NaiveDateTime,
    pub responded_at: Option<NaiveDateTime>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShareDetail {
    pub share: ShareRecord,
    pub from_user: UserProfile,
    pub target_user: UserProfile,
    pub item: ClipboardItem,
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceptedShare {
    pub share: ShareRecord,
    pub copied_item: ClipboardItem,
}

#[derive(Debug)]
pub enum ShareServiceError {
    Validation(String),
    NotFound,
    Conflict,
    Database(sqlx::Error),
}

pub async fn create_share(
    db: &Pool<Postgres>,
    from_user_id: UserId,
    item_id: i64,
    target_user_id: UserId,
    message: Option<String>,
) -> Result<ShareRecord, ShareServiceError> {
    if from_user_id == target_user_id {
        return Err(ShareServiceError::Validation(
            "cannot share an item with yourself".to_string(),
        ));
    }

    if !friend_service::are_friends(db, from_user_id, target_user_id).await? {
        return Err(ShareServiceError::Validation(
            "can only share clipboard items with accepted friends".to_string(),
        ));
    }

    let share = sqlx::query_as::<_, ShareRecord>(
        r#"
        INSERT INTO shares (item_id, from_user_id, target_user_id, message)
        VALUES ($1, $2, $3, $4)
        RETURNING id, item_id, from_user_id, target_user_id, status, message,
                  created_at, responded_at
        "#,
    )
    .bind(item_id)
    .bind(from_user_id)
    .bind(target_user_id)
    .bind(message.as_deref().map(str::trim))
    .fetch_one(db)
    .await
    .map_err(map_create_error)?;

    Ok(share)
}

pub async fn incoming(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Vec<ShareDetail>, ShareServiceError> {
    list_shares(db, user_id, ShareDirection::Incoming).await
}

pub async fn outgoing(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Vec<ShareDetail>, ShareServiceError> {
    list_shares(db, user_id, ShareDirection::Outgoing).await
}

pub async fn accept(
    db: &Pool<Postgres>,
    target_user_id: UserId,
    share_id: i64,
) -> Result<AcceptedShare, ShareServiceError> {
    let mut tx = db.begin().await?;

    let share = sqlx::query_as::<_, ShareRecord>(
        r#"
        UPDATE shares
        SET status = 'accepted', responded_at = NOW()
        WHERE id = $1 AND target_user_id = $2 AND status = 'pending'
        RETURNING id, item_id, from_user_id, target_user_id, status, message,
                  created_at, responded_at
        "#,
    )
    .bind(share_id)
    .bind(target_user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ShareServiceError::NotFound)?;

    let copied_item = sqlx::query_as::<_, ClipboardItem>(
        r#"
        INSERT INTO clipboard_items (owner_id, content_type, text_content, object_hash, filename)
        SELECT $1, content_type, text_content, object_hash, filename
        FROM clipboard_items
        WHERE id = $2
        RETURNING id, owner_id, content_type, filename, text_content, object_hash,
                  NULL::TEXT AS mime_type, NULL::TEXT AS content_hash, created_at
        "#,
    )
    .bind(target_user_id)
    .bind(share.item_id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(AcceptedShare {
        share,
        copied_item: clipboard_service::decorate_item(copied_item),
    })
}

pub async fn reject(
    db: &Pool<Postgres>,
    target_user_id: UserId,
    share_id: i64,
) -> Result<ShareRecord, ShareServiceError> {
    sqlx::query_as::<_, ShareRecord>(
        r#"
        UPDATE shares
        SET status = 'rejected', responded_at = NOW()
        WHERE id = $1 AND target_user_id = $2 AND status = 'pending'
        RETURNING id, item_id, from_user_id, target_user_id, status, message,
                  created_at, responded_at
        "#,
    )
    .bind(share_id)
    .bind(target_user_id)
    .fetch_optional(db)
    .await?
    .ok_or(ShareServiceError::NotFound)
}

enum ShareDirection {
    Incoming,
    Outgoing,
}

async fn list_shares(
    db: &Pool<Postgres>,
    user_id: UserId,
    direction: ShareDirection,
) -> Result<Vec<ShareDetail>, ShareServiceError> {
    let filter = match direction {
        ShareDirection::Incoming => "s.target_user_id = $1",
        ShareDirection::Outgoing => "s.from_user_id = $1",
    };
    let sql = format!(
        r#"
        SELECT
            s.id AS share_id, s.item_id, s.from_user_id, s.target_user_id,
            s.status, s.message, s.created_at AS share_created_at, s.responded_at,
            fu.id AS from_id, fu.username AS from_username,
            fu.created_at AS from_created_at,
            tu.id AS target_id, tu.username AS target_username,
            tu.created_at AS target_created_at,
            ci.id AS item_id_value, ci.owner_id, ci.content_type,
            ci.filename, ci.text_content, ci.object_hash,
            ci.created_at AS item_created_at
        FROM shares s
        JOIN users fu ON fu.id = s.from_user_id
        JOIN users tu ON tu.id = s.target_user_id
        JOIN clipboard_items ci ON ci.id = s.item_id
        WHERE {filter}
        ORDER BY s.created_at DESC
        LIMIT 100
        "#
    );

    let rows = sqlx::query_as::<_, ShareDetailRow>(&sql)
        .bind(user_id)
        .fetch_all(db)
        .await?;

    Ok(rows.into_iter().map(ShareDetail::from).collect())
}

#[derive(sqlx::FromRow)]
struct ShareDetailRow {
    share_id: i64,
    item_id: i64,
    from_user_id: UserId,
    target_user_id: UserId,
    status: String,
    message: Option<String>,
    share_created_at: NaiveDateTime,
    responded_at: Option<NaiveDateTime>,
    from_id: UserId,
    from_username: String,
    from_created_at: NaiveDateTime,
    target_id: UserId,
    target_username: String,
    target_created_at: NaiveDateTime,
    item_id_value: i64,
    owner_id: UserId,
    content_type: String,
    filename: Option<String>,
    text_content: Option<String>,
    object_hash: Option<String>,
    item_created_at: NaiveDateTime,
}

impl From<ShareDetailRow> for ShareDetail {
    fn from(row: ShareDetailRow) -> Self {
        Self {
            share: ShareRecord {
                id: row.share_id,
                item_id: row.item_id,
                from_user_id: row.from_user_id,
                target_user_id: row.target_user_id,
                status: row.status,
                message: row.message,
                created_at: row.share_created_at,
                responded_at: row.responded_at,
            },
            from_user: UserProfile {
                id: row.from_id,
                username: row.from_username,
                created_at: row.from_created_at,
            },
            target_user: UserProfile {
                id: row.target_id,
                username: row.target_username,
                created_at: row.target_created_at,
            },
            item: clipboard_service::decorate_item(ClipboardItem {
                id: row.item_id_value,
                owner_id: row.owner_id,
                content_type: row.content_type,
                filename: row.filename,
                text_content: row.text_content,
                object_hash: row.object_hash,
                mime_type: None,
                content_hash: None,
                created_at: row.item_created_at,
            }),
        }
    }
}

fn map_create_error(error: sqlx::Error) -> ShareServiceError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.constraint() == Some("shares_item_target_idx") {
            return ShareServiceError::Conflict;
        }
        if db_error.constraint() == Some("shares_item_id_from_user_id_fkey") {
            return ShareServiceError::NotFound;
        }
    }
    ShareServiceError::Database(error)
}

impl From<sqlx::Error> for ShareServiceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
