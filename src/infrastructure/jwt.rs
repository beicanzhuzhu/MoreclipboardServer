use crate::domain::UserId;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{
    env,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const ACCESS_TTL_SECONDS: usize = 15 * 60;
pub const REFRESH_TTL_SECONDS: usize = 7 * 24 * 60 * 60;

static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: UserId,
    pub device_id: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub token_type: TokenType,
    pub is_admin: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
}

pub fn access_claims(user_id: UserId, device_id: String, is_admin: bool) -> Claims {
    claims(
        user_id,
        device_id,
        is_admin,
        TokenType::Access,
        ACCESS_TTL_SECONDS,
    )
}

pub fn refresh_claims(user_id: UserId, device_id: String, is_admin: bool) -> Claims {
    claims(
        user_id,
        device_id,
        is_admin,
        TokenType::Refresh,
        REFRESH_TTL_SECONDS,
    )
}

pub fn encode_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(&jwt_secret()),
    )
}

pub fn decode_access_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let claims = decode_token(token)?;
    if claims.token_type != TokenType::Access {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(claims)
}

pub fn decode_refresh_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let claims = decode_token(token)?;
    if claims.token_type != TokenType::Refresh {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(claims)
}

fn decode_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret()),
        &Validation::default(),
    )
    .map(|data| data.claims)
}

fn claims(
    user_id: UserId,
    device_id: String,
    is_admin: bool,
    token_type: TokenType,
    ttl_seconds: usize,
) -> Claims {
    let issued_at = now_seconds();
    Claims {
        sub: user_id,
        device_id,
        exp: issued_at + ttl_seconds,
        iat: issued_at,
        jti: next_jti(user_id),
        token_type,
        is_admin,
    }
}

fn now_seconds() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before UNIX_EPOCH")
        .as_secs() as usize
}

fn next_jti(user_id: UserId) -> String {
    let counter = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", user_id, now_seconds(), counter)
}

fn jwt_secret() -> Vec<u8> {
    env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")
        .into_bytes()
}
