use crate::{
    domain::{UserId, UserProfile},
    infrastructure::{jwt, password_hash},
};
use chrono::NaiveDateTime;
use sqlx::{Pool, Postgres};

#[derive(Clone, Debug)]
pub struct RegisterInput {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
    pub device_id: Option<String>,
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
    password_hash: String,
    created_at: NaiveDateTime,
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
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        RETURNING id, username, created_at
        "#,
    )
    .bind(input.username.trim())
    .bind(password_hash)
    .fetch_one(db)
    .await
    .map_err(map_create_user_error)?;

    Ok(user)
}

pub async fn login(db: &Pool<Postgres>, input: LoginInput) -> Result<Session, AuthServiceError> {
    let user = sqlx::query_as::<_, LoginUserRow>(
        r#"
        SELECT id, username, password_hash, created_at
        FROM users
        WHERE username = $1
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
        created_at: user.created_at,
    };

    let device_id = normalize_device_id(profile.id, input.device_id.as_deref());
    issue_session(profile, device_id)
}

pub async fn refresh_session(
    db: &Pool<Postgres>,
    refresh_token: &str,
) -> Result<Session, AuthServiceError> {
    let claims =
        jwt::decode_refresh_token(refresh_token).map_err(|_| AuthServiceError::InvalidToken)?;
    let user = get_user_profile(db, claims.sub).await?;
    issue_session(user, claims.device_id)
}

pub async fn logout(
    _db: &Pool<Postgres>,
    _user_id: UserId,
    _device_id: &str,
    _refresh_token: Option<&str>,
) -> Result<(), AuthServiceError> {
    Ok(())
}

pub async fn get_user_profile(
    db: &Pool<Postgres>,
    user_id: UserId,
) -> Result<UserProfile, AuthServiceError> {
    sqlx::query_as::<_, UserProfile>(
        r#"
        SELECT id, username, created_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or(AuthServiceError::NotFound)
}

fn issue_session(user: UserProfile, device_id: String) -> Result<Session, AuthServiceError> {
    let access_claims = jwt::access_claims(user.id, device_id.clone());
    let refresh_claims = jwt::refresh_claims(user.id, device_id);
    let access_token =
        jwt::encode_token(&access_claims).map_err(|_| AuthServiceError::TokenFailed)?;
    let refresh_token =
        jwt::encode_token(&refresh_claims).map_err(|_| AuthServiceError::TokenFailed)?;

    Ok(Session {
        user,
        access_token,
        refresh_token,
        expires_in: jwt::ACCESS_TTL_SECONDS,
    })
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
