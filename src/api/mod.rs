pub mod auth;
pub mod clipboard;
pub mod realtime;
mod response;
pub mod shares;
pub mod users;

use crate::app_state::AppState;
use axum::Router;
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(auth::router())
        .merge(users::router())
        .merge(clipboard::router())
        .merge(shares::router())
        .merge(realtime::router())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_router_builds() {
        let _router = router();
    }
}
