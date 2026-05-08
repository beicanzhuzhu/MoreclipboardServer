use crate::{app_state::AppState, domain::AuthenticatedUser};
use axum::{
    extract::{Extension, State},
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Router,
};
use futures::{Stream, StreamExt};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio_stream::wrappers::BroadcastStream;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/events", get(events))
}

async fn events(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.subscribe(user.user_id);
    let stream = BroadcastStream::new(rx).filter_map(|event| async move {
        match event {
            Ok(event) => serde_json::to_string(&event)
                .ok()
                .map(|payload| Ok(Event::default().data(payload))),
            Err(_) => Some(Ok(Event::default().event("lagged").data("event_lagged"))),
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
}
