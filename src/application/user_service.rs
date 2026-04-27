use crate::domain::{UserId, UserProfile};
use sqlx::{Pool, Postgres};

pub async fn search_users(
    db: &Pool<Postgres>,
    current_user_id: UserId,
    query: &str,
) -> Result<Vec<UserProfile>, sqlx::Error> {
    let query = query.trim();
    if query.is_empty() {
        return Ok(Vec::new());
    }

    let pattern = format!("%{}%", query);
    sqlx::query_as::<_, UserProfile>(
        r#"
        SELECT id, username, display_name, is_admin, created_at
        FROM users
        WHERE deleted_at IS NULL
          AND id <> $1
          AND (username ILIKE $2 OR display_name ILIKE $2)
        ORDER BY username ASC
        LIMIT 20
        "#,
    )
    .bind(current_user_id)
    .bind(pattern)
    .fetch_all(db)
    .await
}
