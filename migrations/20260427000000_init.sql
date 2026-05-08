CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    password_hash TEXT NOT NULL,
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (id, user_id)
);

CREATE TABLE IF NOT EXISTS local_objects (
    hash VARCHAR(64) PRIMARY KEY,
    byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
    mime_type VARCHAR(255),
    storage_path TEXT GENERATED ALWAYS AS (
        'objects/' ||
        substring(hash from 1 for 2) || '/' ||
        substring(hash from 3 for 2) || '/' ||
        substring(hash from 5)
    ) STORED,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMP,
    CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS clipboard_items (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(32) NOT NULL DEFAULT 'text',
    mime_type VARCHAR(255),
    filename TEXT,
    summary TEXT,
    text_content TEXT,
    object_hash VARCHAR(64) REFERENCES local_objects(hash) ON DELETE RESTRICT,
    thumbnail_hash VARCHAR(64) REFERENCES local_objects(hash) ON DELETE RESTRICT,
    content_hash VARCHAR(64),
    source_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,
    UNIQUE (id, owner_id),
    CHECK (content_type IN ('text', 'image', 'file', 'file_list', 'binary')),
    CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
    CHECK (thumbnail_hash IS NULL OR content_type = 'image'),
    CHECK (
        (content_type = 'text' AND (
            (text_content IS NOT NULL AND object_hash IS NULL) OR
            (text_content IS NULL AND object_hash IS NOT NULL)
        )) OR
        (content_type IN ('image', 'file', 'binary') AND text_content IS NULL AND object_hash IS NOT NULL) OR
        (content_type = 'file_list' AND text_content IS NOT NULL AND object_hash IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS current_clipboards (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    clipboard_item_id BIGINT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    FOREIGN KEY (clipboard_item_id, user_id) REFERENCES clipboard_items(id, owner_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS clipboard_file_entries (
    id BIGSERIAL PRIMARY KEY,
    item_id BIGINT NOT NULL REFERENCES clipboard_items(id) ON DELETE CASCADE,
    object_hash VARCHAR(64) REFERENCES local_objects(hash) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    relative_path TEXT,
    mime_type VARCHAR(255),
    byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
    position INTEGER NOT NULL CHECK (position >= 0),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (item_id, position)
);

CREATE TABLE IF NOT EXISTS shares (
    id BIGSERIAL PRIMARY KEY,
    item_id BIGINT NOT NULL,
    from_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMP,
    FOREIGN KEY (item_id, from_user_id) REFERENCES clipboard_items(id, owner_id) ON DELETE CASCADE,
    CHECK (from_user_id <> target_user_id),
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

CREATE UNIQUE INDEX IF NOT EXISTS shares_item_target_idx
    ON shares (item_id, from_user_id, target_user_id)
    WHERE status IN ('pending', 'accepted');

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS users_username_trgm_idx
    ON users USING GIN (username gin_trgm_ops)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS users_display_name_trgm_idx
    ON users USING GIN (display_name gin_trgm_ops)
    WHERE deleted_at IS NULL AND display_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS devices_user_id_idx ON devices (user_id);
CREATE INDEX IF NOT EXISTS local_objects_created_idx ON local_objects (created_at DESC);
CREATE INDEX IF NOT EXISTS clipboard_items_owner_created_idx
    ON clipboard_items (owner_id, created_at DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS clipboard_items_owner_hash_idx
    ON clipboard_items (owner_id, content_hash)
    WHERE deleted_at IS NULL AND content_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS clipboard_items_object_hash_idx
    ON clipboard_items (object_hash)
    WHERE object_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS clipboard_items_thumbnail_hash_idx
    ON clipboard_items (thumbnail_hash)
    WHERE thumbnail_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS current_clipboards_item_idx
    ON current_clipboards (clipboard_item_id);
CREATE INDEX IF NOT EXISTS clipboard_file_entries_item_idx
    ON clipboard_file_entries (item_id, position);
CREATE INDEX IF NOT EXISTS clipboard_file_entries_object_hash_idx
    ON clipboard_file_entries (object_hash)
    WHERE object_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS shares_incoming_idx
    ON shares (target_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS shares_outgoing_idx
    ON shares (from_user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_device_active_idx
    ON refresh_tokens (user_id, device_id)
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
