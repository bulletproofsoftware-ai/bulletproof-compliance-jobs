-- 001_add_signature_columns.sql
--
-- PRD 18 REQ-RCA-013: add Ed25519 signature columns to regulatory_runs and
-- merkle_roots so signed evidence packages can be persisted alongside the
-- existing SHA-256 integrity hashes.
--
-- This is the canonical migration file. The same logic runs automatically
-- and idempotently in app/db.py:_apply_additive_migrations() on every
-- container start, so this file is documentation / manual-run companion.
--
-- Idempotency note: SQLite does NOT support `ALTER TABLE ... ADD COLUMN IF
-- NOT EXISTS`. The application performs the equivalent check via
-- `PRAGMA table_info(<table>)` before issuing each ALTER. If you need to run
-- this script manually, do so against a database that does NOT yet have
-- these columns, or check first with:
--
--     PRAGMA table_info(regulatory_runs);
--     PRAGMA table_info(merkle_roots);

ALTER TABLE regulatory_runs ADD COLUMN signing_key_id TEXT;
ALTER TABLE merkle_roots ADD COLUMN signature TEXT;
ALTER TABLE merkle_roots ADD COLUMN signing_key_id TEXT;
