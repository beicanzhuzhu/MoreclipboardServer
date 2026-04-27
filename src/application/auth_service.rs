use crate::{
    domain::{UserId, UserProfile},
    infrastructure::{jwt, password_hash},
};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{Pool, Postgres};

#[derive(Clone, Debug)]
pub struct RegisterInput {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub platform: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub user: UserProfile,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
}

#[derive(sqlx::FromRow)]
struct LoginUserRow {
    id: UserId,
    username: String,
    display_name: Option<String>,
    password_hash: String,
    is_admin: bool,
    created_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    token_hash: String,
}

pub async fn register(
    db: &Pool<Postgres>,
    input: RegisterInput,
) -> Result<UserProfile, AuthServiceError> {
    validate_username(&input.username)?;
    validate_password(&input.password)?;

    let password_hash =
        password_hash::hash_secret(&input.password).map_err(|_| AuthServiceError::HashFailed)?;

    let user = sqlx::query_as::<_, UserProfile>(
        r#"
        INSERT INTO users (username, display_name, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, username, display_name, is_admin, created_at
        "#,
    )
    .bind(input.username.trim())
    .bind(input.display_name.as_deref().map(str::trim))
    .bind(password_hash)
    .fetch_one(db)
    .await
    .map_err(map_create_user_error)?;

    Ok(user)
}

pub async fn login(db: &Pool<Postgres>, input: LoginInput) -> Result<Session, AuthServiceError> {
    let user = sqlx::query_as::<_, LoginUserRow>(
        r#"
        SELECT id, username, display_name, password_hash, is_admin, created_at
        FROM users
        WHERE username = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(input.username.trim())
    .fetch_optional(db)
    .await?
    .ok_or(AuthServiceError::InvalidCredentials)?;

    if !password_hash::verify_secret(&input.password, &user.password_hash) {
        return Err(AuthServiceError::InvalidCredentials);
    }

    let profile = UserProfile {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_admin: user.is_admin,
        created_at: user.created_at,
    };

    let device_id = normalize_device_id(profile.id, input.device_id.as_deref());
    upsert_device(
        db,
        profile.id,
        &device_id,
        input.device_name.as_deref(),
        input.platform.as_deref(),
    )
    .await?;

    issue_session(db, profile, device_id).await
}

pub async fn refresh_session(
    db: &Pool<Postgres>,
    refresh_token: &str,
) -> Result<Session, AuthServiceError> {
    let claims =
        jwt::decode_refresh_token(refresh_token).map_err(|_| AuthServiceError::InvalidToken)?;

    let stored = sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        SELECT token_hash
        FROM refresh_tokens
        WHERE jti = $1
          AND user_id = $2
          AND revoked_at IS NULL
          AND expires_at > NOW()
        "#,
    )
    .bind(&claims.jti)
    .bind(claims.sub)
    .fetch_optional(db)
    .await?
    .ok_or(AuthServiceError::InvalidToken)?;

    if !password_hash::verify_secret(refresh_token, &stored.token_hash) {
        return Err(AuthServiceError::InvalidToken);
    }

    revoke_refresh_token(db, claims.sub, &claims.jti).await?;

    let user = get_user_profile(db, claims.sub).await?;
    issue_session(db, user, claims.device_id).await
}

pub async fn logout(
    db: &Pool<Postgres>,
    user_id: UserId,
    device_id: &str,
    refresh_token: Option<&str>,
) -> Result<(), AuthServiceError> {
    if let Some(refresh_token) = refresh_token {
        let claims =
            jwt::decode_refresh_token(refresh_token).map_err(|_| AuthServiceError::InvalidToken)?;
        if claims.sub != user_id {
            return Err(AuthServiceError::InvalidToken);
        }
        revoke_refresh_token(db, user_id, &claims.jti).await?;
        return Ok(());
    }

    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .execute(db)
    .await?;

    Ok(())
}

pub async fn get_user_profile(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<UserProfile, AuthServiceError> {
    sqlx::query_as::<_, UserProfile>(
        r#"
        SELECT id, username, display_name, is_admin, created_at
        FROM users
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or(AuthServiceError::NotFound)
}

async fn issue_session(
    db: &Pool<Postgres>,
    user: UserProfile,
    device_id: String,
) -> Result<Session, AuthServiceError> {
    let access_claims = jwt::access_claims(user.id, device_id.clone(), user.is_admin);
    let refresh_claims = jwt::refresh_claims(user.id, device_id.clone(), user.is_admin);
    let access_token =
        jwt::encode_token(&access_claims).map_err(|_| AuthServiceError::TokenFailed)?;
    let refresh_token =
        jwt::encode_token(&refresh_claims).map_err(|_| AuthServiceError::TokenFailed)?;

    store_refresh_token(db, user.id, &device_id, &refresh_claims, &refresh_token).await?;

    Ok(Session {
        user,
        access_token,
        refresh_token,
        expires_in: jwt::ACCESS_TTL_SECONDS,
    })
}

async fn store_refresh_token(
    db: &Pool<Postgres>,
    user_id: UserId,
    device_id: &str,
    claims: &jwt::Claims,
    refresh_token: &str,
) -> Result<(), AuthServiceError> {
    let token_hash =
        password_hash::hash_secret(refresh_token).map_err(|_| AuthServiceError::HashFailed)?;
    let expires_at = timestamp_to_naive(claims.exp)?;

    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (jti, user_id, device_id, token_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&claims.jti)
    .bind(user_id)
    .bind(device_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(db)
    .await?;

    Ok(())
}

async fn revoke_refresh_token(
    db: &Pool<Postgres>,
    user_id: UserId,
    jti: &str,
) -> Result<(), AuthServiceError> {
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND jti = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(user_id)
    .bind(jti)
    .execute(db)
    .await?;

    Ok(())
}

async fn upsert_device(
    db: &Pool<Postgres>,
    user_id: UserId,
    device_id: &str,
    device_name: Option<&str>,
    platform: Option<&str>,
) -> Result<(), AuthServiceError> {
    sqlx::query(
        r#"
        INSERT INTO devices (id, user_id, device_name, platform, last_seen_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (id) DO UPDATE
        SET device_name = COALESCE(EXCLUDED.device_name, devices.device_name),
            platform = COALESCE(EXCLUDED.platform, devices.platform),
            last_seen_at = NOW()
        "#,
    )
    .bind(device_id)
    .bind(user_id)
    .bind(device_name.map(str::trim))
    .bind(platform.map(str::trim))
    .execute(db)
    .await?;

    Ok(())
}

fn normalize_device_id(user_id: UserId, device_id: Option<&str>) -> String {
    let suffix = device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("default");
    format!("user-{}:{}", user_id, suffix)
}

fn validate_username(username: &str) -> Result<(), AuthServiceError> {
    let username = username.trim();
    if username.len() < 3 || username.len() > 255 {
        return Err(AuthServiceError::Validation(
            "username length must be between 3 and 255".to_string(),
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AuthServiceError> {
    if password.len() < 8 {
        return Err(AuthServiceError::Validation(
            "password length must be at least 8".to_string(),
        ));
    }
    Ok(())
}

fn timestamp_to_naive(timestamp: usize) -> Result<NaiveDateTime, AuthServiceError> {
    DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .map(|value| value.naive_utc())
        .ok_or_else(|| AuthServiceError::Validation("invalid token expiration".to_string()))
}

fn map_create_user_error(error: sqlx::Error) -> AuthServiceError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.constraint() == Some("users_username_key") {
            return AuthServiceError::UsernameTaken;
        }
    }
    AuthServiceError::Database(error)
}

#[derive(Debug)]
pub enum AuthServiceError {
    Validation(String),
    UsernameTaken,
    InvalidCredentials,
    InvalidToken,
    NotFound,
    HashFailed,
    TokenFailed,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for AuthServiceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
