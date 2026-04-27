CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(255),
    platform VARCHAR(64),
    last_seen_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clipboard_items (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(32) NOT NULL DEFAULT 'text',
    mime_type VARCHAR(255),
    summary TEXT,
    text_content TEXT,
    object_key TEXT,
    thumbnail_key TEXT,
    content_hash VARCHAR(128),
    source_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,
    CHECK (content_type IN ('text', 'image', 'file_list', 'binary'))
);

CREATE TABLE IF NOT EXISTS current_clipboards (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    clipboard_item_id BIGINT NOT NULL REFERENCES clipboard_items(id) ON DELETE CASCADE,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS shares (
    id BIGSERIAL PRIMARY KEY,
    item_id BIGINT REFERENCES clipboard_items(id) ON DELETE CASCADE,
    from_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'accepted',
    message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMP,
    CHECK (status IN ('pending', 'accepted', 'rejected', 'cancelled'))
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Compatibility table for the current API. New clipboard APIs should move to
-- clipboard_items + current_clipboards and then this table can be retired.
CREATE TABLE IF NOT EXISTS user_data (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS shares_pair_without_item_idx
    ON shares (from_user_id, target_user_id)
    WHERE item_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS shares_item_target_idx
    ON shares (item_id, from_user_id, target_user_id)
    WHERE item_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS devices_user_id_idx ON devices (user_id);
CREATE INDEX IF NOT EXISTS clipboard_items_owner_created_idx
    ON clipboard_items (owner_id, created_at DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS shares_incoming_idx
    ON shares (target_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS shares_outgoing_idx
    ON shares (from_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens (user_id);
