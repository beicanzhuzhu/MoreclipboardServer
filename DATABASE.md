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
