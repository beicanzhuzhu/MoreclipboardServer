# Database Setup

## Local Development

Create a local environment file:

```bash
cp .env.example .env
```

Start PostgreSQL:

```bash
docker compose up -d postgres
```

Run the server:

```bash
cargo run
```

The server runs SQLx migrations on startup, so a fresh database will be
initialized automatically.

Large clipboard payloads are stored on local disk, not in PostgreSQL. Configure
the local object root with:

```bash
LOCAL_OBJECT_STORE_DIR=./var/object-store
```

Objects are addressed by SHA-256 and laid out like Git objects:

```text
objects/ab/cd/ef...
```

PostgreSQL stores only object metadata and references.

## Current Schema

The project intentionally uses five application tables:

```text
users
objects
clipboard_items
friendships
shares
```

`clipboard_items` is both the current clipboard source and the history table:

- current clipboard: newest item for `owner_id`
- paged history: `GET /api/v1/clipboard/history?limit=20&cursor=...`
- full history: `GET /api/v1/clipboard/history?all=true`

`friendships` stores pending/accepted friend relationships. A clipboard item can
only be shared to an accepted friend.

File paths are not stored in PostgreSQL. The server derives them from
`objects.hash` with `objects/ab/cd/ef...`.

## Useful Checks

Check container health:

```bash
docker compose ps
```

Inspect tables:

```bash
docker compose exec postgres psql -U postgres -d moreclipboard -c '\dt'
```

Reset the local database:

```bash
docker compose down -v
```
