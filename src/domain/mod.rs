//! Domain layer.
//!
//! Core models and value objects should be added here as the API moves beyond
//! routing placeholders.

use chrono::NaiveDateTime;
use serde::Serialize;

pub type UserId = i64;

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub device_id: String,
    pub is_admin: bool,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct UserProfile {
    pub id: UserId,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub created_at: NaiveDateTime,
}
