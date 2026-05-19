use crate::domain::{UserId, UserProfile};
use chrono::NaiveDateTime;
use serde::Serialize;
use sqlx::{Pool, Postgres};

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct FriendshipRecord {
    pub id: i64,
    pub requester_id: UserId,
    pub addressee_id: UserId,
    pub status: String,
    pub message: Option<String>,
    pub created_at: NaiveDateTime,
    pub responded_at: Option<NaiveDateTime>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FriendshipDetail {
    pub friendship: FriendshipRecord,
    pub requester: UserProfile,
    pub addressee: UserProfile,
}

#[derive(Clone, Debug, Serialize)]
pub struct FriendSummary {
    pub friendship: FriendshipRecord,
    pub friend: UserProfile,
}

#[derive(Debug)]
pub enum FriendServiceError {
    Validation(String),
    NotFound,
    Conflict,
    Database(sqlx::Error),
}

pub async fn create_request(
    db: &Pool<Postgres>,
    requester_id: UserId,
    addressee_id: UserId,
    message: Option<String>,
) -> Result<FriendshipDetail, FriendServiceError> {
    if requester_id == addressee_id {
        return Err(FriendServiceError::Validation(
            "cannot add yourself as a friend".to_string(),
        ));
    }

    let message = message
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let friendship = sqlx::query_as::<_, FriendshipRecord>(
        r#"
        INSERT INTO friendships (requester_id, addressee_id, message)
        VALUES ($1, $2, $3)
        RETURNING id, requester_id, addressee_id, status, message,
                  created_at, responded_at
        "#,
    )
    .bind(requester_id)
    .bind(addressee_id)
    .bind(message)
    .fetch_one(db)
    .await
    .map_err(map_create_error)?;

    detail(db, friendship.id).await
}

pub async fn friends(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Vec<FriendSummary>, FriendServiceError> {
    let rows = sqlx::query_as::<_, FriendshipDetailRow>(
        r#"
        SELECT
            f.id AS friendship_id, f.requester_id, f.addressee_id,
            f.status, f.message, f.created_at AS friendship_created_at,
            f.responded_at,
            ru.id AS requester_user_id, ru.username AS requester_username,
            ru.created_at AS requester_created_at,
            au.id AS addressee_user_id, au.username AS addressee_username,
            au.created_at AS addressee_created_at
        FROM friendships f
        JOIN users ru ON ru.id = f.requester_id
        JOIN users au ON au.id = f.addressee_id
        WHERE f.status = 'accepted'
          AND (f.requester_id = $1 OR f.addressee_id = $1)
        ORDER BY COALESCE(f.responded_at, f.created_at) DESC, f.id DESC
        LIMIT 100
        "#,
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(FriendshipDetail::from)
        .map(|detail| {
            let friend = if detail.friendship.requester_id == user_id {
                detail.addressee.clone()
            } else {
                detail.requester.clone()
            };
            FriendSummary {
                friendship: detail.friendship,
                friend,
            }
        })
        .collect())
}

pub async fn incoming(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Vec<FriendshipDetail>, FriendServiceError> {
    list_requests(db, user_id, FriendDirection::Incoming).await
}

pub async fn outgoing(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<Vec<FriendshipDetail>, FriendServiceError> {
    list_requests(db, user_id, FriendDirection::Outgoing).await
}

pub async fn accept(
    db: &Pool<Postgres>,
    addressee_id: UserId,
    friendship_id: i64,
) -> Result<FriendshipDetail, FriendServiceError> {
    let friendship = sqlx::query_as::<_, FriendshipRecord>(
        r#"
        UPDATE friendships
        SET status = 'accepted', responded_at = NOW()
        WHERE id = $1 AND addressee_id = $2 AND status = 'pending'
        RETURNING id, requester_id, addressee_id, status, message,
                  created_at, responded_at
        "#,
    )
    .bind(friendship_id)
    .bind(addressee_id)
    .fetch_optional(db)
    .await?
    .ok_or(FriendServiceError::NotFound)?;

    detail(db, friendship.id).await
}

pub async fn reject(
    db: &Pool<Postgres>,
    addressee_id: UserId,
    friendship_id: i64,
) -> Result<FriendshipDetail, FriendServiceError> {
    let friendship = sqlx::query_as::<_, FriendshipRecord>(
        r#"
        UPDATE friendships
        SET status = 'rejected', responded_at = NOW()
        WHERE id = $1 AND addressee_id = $2 AND status = 'pending'
        RETURNING id, requester_id, addressee_id, status, message,
                  created_at, responded_at
        "#,
    )
    .bind(friendship_id)
    .bind(addressee_id)
    .fetch_optional(db)
    .await?
    .ok_or(FriendServiceError::NotFound)?;

    detail(db, friendship.id).await
}

pub async fn are_friends(
    db: &Pool<Postgres>,
    first_user_id: UserId,
    second_user_id: UserId,
) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM friendships
            WHERE status = 'accepted'
              AND (
                (requester_id = $1 AND addressee_id = $2)
                OR
                (requester_id = $2 AND addressee_id = $1)
              )
        )
        "#,
    )
    .bind(first_user_id)
    .bind(second_user_id)
    .fetch_one(db)
    .await?;

    Ok(exists)
}

async fn detail(
    db: &Pool<Postgres>,
    friendship_id: i64,
) -> Result<FriendshipDetail, FriendServiceError> {
    let row = sqlx::query_as::<_, FriendshipDetailRow>(
        r#"
        SELECT
            f.id AS friendship_id, f.requester_id, f.addressee_id,
            f.status, f.message, f.created_at AS friendship_created_at,
            f.responded_at,
            ru.id AS requester_user_id, ru.username AS requester_username,
            ru.created_at AS requester_created_at,
            au.id AS addressee_user_id, au.username AS addressee_username,
            au.created_at AS addressee_created_at
        FROM friendships f
        JOIN users ru ON ru.id = f.requester_id
        JOIN users au ON au.id = f.addressee_id
        WHERE f.id = $1
        "#,
    )
    .bind(friendship_id)
    .fetch_optional(db)
    .await?
    .ok_or(FriendServiceError::NotFound)?;

    Ok(row.into())
}

enum FriendDirection {
    Incoming,
    Outgoing,
}

async fn list_requests(
    db: &Pool<Postgres>,
    user_id: UserId,
    direction: FriendDirection,
) -> Result<Vec<FriendshipDetail>, FriendServiceError> {
    let filter = match direction {
        FriendDirection::Incoming => "f.addressee_id = $1",
        FriendDirection::Outgoing => "f.requester_id = $1",
    };
    let sql = format!(
        r#"
        SELECT
            f.id AS friendship_id, f.requester_id, f.addressee_id,
            f.status, f.message, f.created_at AS friendship_created_at,
            f.responded_at,
            ru.id AS requester_user_id, ru.username AS requester_username,
            ru.created_at AS requester_created_at,
            au.id AS addressee_user_id, au.username AS addressee_username,
            au.created_at AS addressee_created_at
        FROM friendships f
        JOIN users ru ON ru.id = f.requester_id
        JOIN users au ON au.id = f.addressee_id
        WHERE {filter}
          AND f.status = 'pending'
        ORDER BY f.created_at DESC, f.id DESC
        LIMIT 100
        "#
    );

    let rows = sqlx::query_as::<_, FriendshipDetailRow>(&sql)
        .bind(user_id)
        .fetch_all(db)
        .await?;

    Ok(rows.into_iter().map(FriendshipDetail::from).collect())
}

#[derive(sqlx::FromRow)]
struct FriendshipDetailRow {
    friendship_id: i64,
    requester_id: UserId,
    addressee_id: UserId,
    status: String,
    message: Option<String>,
    friendship_created_at: NaiveDateTime,
    responded_at: Option<NaiveDateTime>,
    requester_user_id: UserId,
    requester_username: String,
    requester_created_at: NaiveDateTime,
    addressee_user_id: UserId,
    addressee_username: String,
    addressee_created_at: NaiveDateTime,
}

impl From<FriendshipDetailRow> for FriendshipDetail {
    fn from(row: FriendshipDetailRow) -> Self {
        Self {
            friendship: FriendshipRecord {
                id: row.friendship_id,
                requester_id: row.requester_id,
                addressee_id: row.addressee_id,
                status: row.status,
                message: row.message,
                created_at: row.friendship_created_at,
                responded_at: row.responded_at,
            },
            requester: UserProfile {
                id: row.requester_user_id,
                username: row.requester_username,
                created_at: row.requester_created_at,
            },
            addressee: UserProfile {
                id: row.addressee_user_id,
                username: row.addressee_username,
                created_at: row.addressee_created_at,
            },
        }
    }
}

fn map_create_error(error: sqlx::Error) -> FriendServiceError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.constraint() == Some("friendships_pair_active_idx") {
            return FriendServiceError::Conflict;
        }
        if db_error.constraint() == Some("friendships_addressee_id_fkey") {
            return FriendServiceError::NotFound;
        }
    }
    FriendServiceError::Database(error)
}

impl From<sqlx::Error> for FriendServiceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
