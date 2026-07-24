# Install — bulletproof-compliance-jobs

## Requirements

- **Python 3.12** (the container base is `python:3.12-slim`).
- A C toolchain is not required for a normal install — all dependencies ship
  wheels. PyNaCl (libsodium) and `psycopg[binary]` are used for signing and
  Postgres access respectively.
- Read access to one or more external audit SQLite databases (optional at start;
  the service degrades gracefully when they are absent).
- Optional: a Qdrant instance if you use the DSR erasure cascade.

## Local install (virtualenv)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Run the service:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8087
```

On first start the service:

1. Creates every state directory it needs (`ensure_dirs()` in `app/config.py`).
2. Initialises the SQLite schema and applies additive migrations (`app/db.py`).
3. Generates an Ed25519 signing keypair under `SIGNING_KEY_DIR` if none exists,
   logging the new `key_id` once (the private key is never logged).
4. Starts the four background schedulers.

Confirm it is up:

```bash
curl -s http://localhost:8087/health | python3 -m json.tool
```

You should see `"status": "ok"` plus the list of active components and the
configured audit databases.

## Docker

A production `Dockerfile` is included. It runs as an unprivileged user
(`appuser`, uid 10001) and ships a healthcheck.

```bash
docker build -t bulletproof-compliance-jobs .

docker run --rm -p 8087:8087 \
  -v "$PWD/state:/state" \
  -v /path/to/governance/audit.db:/governance/audit.db:ro \
  -v /path/to/security/audit_bus.sqlite:/security/audit_bus.sqlite:ro \
  bulletproof-compliance-jobs
```

- `/state` is the writable volume for local SQLite, Merkle roots, archives,
  DSR confirmations, reports, and signing keys. **Persist it** — losing it loses
  the signing key and the Merkle chain history.
- Audit databases are mounted **read-only** (`:ro`). The retention enforcer
  detects a read-only mount and switches to archive-only mode automatically
  (it reports `cannot_delete=true`).

Verify the container runs as non-root:

```bash
docker run --rm --entrypoint sh bulletproof-compliance-jobs -c 'id -un'   # -> appuser
```

## Configuration

All configuration is environment-driven (`app/config.py`). Nothing is required to
boot; sensible defaults apply. The most common overrides:

| Env var | Default | Purpose |
|---|---|---|
| `SQLITE_PATH` | `/state/compliance_jobs.sqlite` | Local state DB path |
| `AUDIT_BUS_DBS` | `/governance/audit.db,/security/audit_bus.sqlite` | Comma-separated external audit DBs (read-only) |
| `SIGNING_KEY_DIR` | `/state/signing-keys` | Ed25519 key material |
| `ARCHIVE_DIR` | `/state/archive` | Compressed retention archives |
| `REPORTS_DIR` | `/state/regulatory-reports` | Signed report artifacts |
| `MERKLE_ROOTS_DIR` | `/state/merkle-roots` | Immutable per-root JSON files |
| `AUDIT_RETENTION_YEARS` | `7` | Retention horizon for audit data |
| `RETENTION_INTERVAL_HOURS` | `24` | Retention sweep cadence |
| `ANNUAL_CHECK_HOURS` | `1` | Annual-report due-check cadence |
| `NAIC_POLL_SECONDS` | `300` | Adverse-action poll cadence |
| `QDRANT_URL` / `QDRANT_API_KEY` | `http://qdrant:6333` / *(empty)* | DSR erasure target |
| `MERKLE_PUBLISH_URL` / `MERKLE_PUBLISH_TOKEN` | *(empty)* | Optional external write-once endpoint for Merkle roots |

See [ADMINISTRATOR.md](ADMINISTRATOR.md) for the full list and operational notes.

## Migrations

Schema creation and additive column migrations run automatically and idempotently
on every start (`app/db.py:_apply_additive_migrations`). SQLite has no
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so the service introspects with
`PRAGMA table_info` before each `ALTER`.

A manual/companion migration is provided at
`migrations/001_add_signature_columns.sql` for operators who prefer to apply
schema changes explicitly. It is documentation-equivalent to what the app does at
startup.

## Development / tests

```bash
pip install -r requirements.txt
python -m pytest tests/
```

The test suite (`tests/`) is hermetic — it pins every state directory into a
per-test temp dir via environment variables and creates throwaway audit databases,
so it needs no external services.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
