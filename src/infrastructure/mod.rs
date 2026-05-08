//! Infrastructure layer.
//!
//! Keep concrete integrations here. At the moment only PostgreSQL setup is
//! active; JWT, hashing, notification, object storage, and thumbnail modules can
//! be introduced when their business flows are implemented.

pub mod database;
pub mod jwt;
pub mod object_store;
pub mod password_hash;
