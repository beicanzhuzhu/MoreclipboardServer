CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS objects (
    hash VARCHAR(64) PRIMARY KEY,
    byte_size BIGINT NOT NULL CHECK (byte_size >= 0),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS clipboard_items (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(32) NOT NULL,
    text_content TEXT,
    object_hash VARCHAR(64) REFERENCES objects(hash) ON DELETE RESTRICT,
    filename TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (id, owner_id),
    CHECK (content_type IN ('text', 'image', 'file', 'file_list', 'binary')),
    CHECK (
        (content_type IN ('text', 'file_list') AND text_content IS NOT NULL AND object_hash IS NULL) OR
        (content_type IN ('image', 'file', 'binary') AND text_content IS NULL AND object_hash IS NOT NULL)
    )
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

CREATE INDEX IF NOT EXISTS clipboard_items_owner_created_idx
    ON clipboard_items (owner_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS clipboard_items_object_hash_idx
    ON clipboard_items (object_hash)
    WHERE object_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS shares_item_target_idx
    ON shares (item_id, from_user_id, target_user_id)
    WHERE status IN ('pending', 'accepted');

CREATE INDEX IF NOT EXISTS shares_incoming_idx
    ON shares (target_user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS shares_outgoing_idx
    ON shares (from_user_id, status, created_at DESC);
