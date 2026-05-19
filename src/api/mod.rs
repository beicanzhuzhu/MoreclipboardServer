pub mod auth;
pub mod clipboard;
pub mod friends;
pub mod realtime;
mod response;
pub mod shares;
pub mod users;

use crate::app_state::AppState;
use axum::{middleware, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    let protected = Router::new()
        .merge(auth::protected_router())
        .merge(users::router())
        .merge(clipboard::router())
        .merge(friends::router())
        .merge(shares::router())
        .merge(realtime::router())
        .route_layer(middleware::from_fn(auth::require_auth));

    Router::new().merge(auth::public_router()).merge(protected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_router_builds() {
        let _router = router();
    }
}
