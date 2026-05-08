use crate::{domain::UserId, infrastructure::object_store::LocalObjectStore};
use dashmap::DashMap;
use serde::Serialize;
use sqlx::{Pool, Postgres};
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Postgres>,
    pub object_store: LocalObjectStore,
    channels: DashMap<UserId, broadcast::Sender<AppEvent>>,
}

impl AppState {
    pub fn new(db: Pool<Postgres>) -> Self {
        Self {
            db,
            object_store: LocalObjectStore::from_env(),
            channels: DashMap::new(),
        }
    }

    pub fn subscribe(&self, user_id: UserId) -> broadcast::Receiver<AppEvent> {
        self.sender_for(user_id).subscribe()
    }

    pub fn notify(&self, user_id: UserId, event: AppEvent) {
        let _ = self.sender_for(user_id).send(event);
    }

    fn sender_for(&self, user_id: UserId) -> broadcast::Sender<AppEvent> {
        if let Some(entry) = self.channels.get(&user_id) {
            return entry.value().clone();
        }

        let (tx, _rx) = broadcast::channel(128);
        self.channels.insert(user_id, tx.clone());
        tx
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum AppEvent {
    ClipboardUpdated {
        item_id: i64,
        source_device_id: String,
        updated_at: String,
    },
    ClipboardDeleted {
        item_id: i64,
        source_device_id: String,
        updated_at: String,
    },
    ShareReceived {
        share_id: i64,
        item_id: i64,
        from_user_id: UserId,
        message: Option<String>,
        created_at: String,
    },
    ShareResponded {
        share_id: i64,
        item_id: i64,
        target_user_id: UserId,
        status: String,
        responded_at: String,
    },
}
