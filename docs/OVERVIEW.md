# Overview — bulletproof-compliance-jobs

`bulletproof-compliance-jobs` is a small FastAPI service that runs the recurring
background jobs a compliance program depends on. It enforces data-retention
policies, cascades Data Subject Requests (DSR) across data stores, and produces
tamper-evident, cryptographically signed audit evidence using an hourly
Merkle-chained log.

It is deliberately self-contained: the service keeps its own operational state in
a local SQLite database and reads *external* audit databases **read-only**. Nothing
in this service mutates the source-of-truth audit trail — it archives, hashes,
signs, and reports on it.

## What it does

| Capability | What runs | Backing code |
|---|---|---|
| **Merkle audit chain** | Hourly job hashes each audit event into a leaf, builds a Merkle tree, chains the new root to the previous one, and signs it (Ed25519). | `app/merkle.py` |
| **Retention enforcement** | Periodic job archives records past their retention horizon to compressed JSONL, then deletes them from source — unless a legal hold is active. | `app/retention.py` |
| **DSR cascade** | On request, purges a subject's data across Qdrant collections and evidence files, then writes a signed deletion-confirmation artifact. Audit references are counted, never deleted (immutable trail). | `app/dsr_cascade.py` |
| **Regulatory reports** | Generates signed JSON evidence packages (SOX, NY DFS Part 500, EU AI Act, NAIC adverse-action). Annual reports auto-fire on a schedule; all can be triggered on demand. | `app/reports.py` |
| **NAIC adverse-action listener** | Polls the audit databases for adverse-action events (policy denials, threat detections, guardian actions) and auto-generates a NAIC artifact per new event, idempotently. | `app/main.py` |
| **Cryptographic signing** | Ed25519 signing key managed on disk with key-id derivation and rotation-aware verification. Exposes public-key and verify endpoints. | `app/signing.py` |

## Architecture at a glance

```
                    ┌──────────────────────────────────────────────┐
                    │            FastAPI service (app.main)          │
                    │                                                │
   external audit   │   ┌────────────┐  ┌───────────────┐           │
   databases (RO)   │   │  merkle    │  │  retention    │           │
   ──────────────►  │   │  publisher │  │  enforcer     │           │
   audit_events     │   └─────┬──────┘  └──────┬────────┘           │
   forensic_events  │         │                │                    │
                    │   ┌─────▼──────┐  ┌──────▼────────┐           │
   Qdrant (DSR)  ◄──┼───│  dsr       │  │  regulatory   │           │
   evidence files   │   │  cascade   │  │  reports      │           │
                    │   └────────────┘  └──────┬────────┘           │
                    │   ┌────────────┐         │                    │
                    │   │  NAIC      │◄────────┘                    │
                    │   │  listener  │   signed with Ed25519         │
                    │   └────────────┘   (app.signing)              │
                    └───────────────┬────────────────────────────────┘
                                    │
                            local SQLite state
                            (merkle_roots, retention_runs,
                             legal_holds, dsr_cascades,
                             regulatory_runs, naic_actions)
```

Four asyncio schedulers start with the service (see `app/main.py:lifespan`):

- **Merkle publisher** — fires a few minutes past each hour.
- **Retention enforcer** — every `RETENTION_INTERVAL_HOURS` (default 24h).
- **Annual report scheduler** — checks every `ANNUAL_CHECK_HOURS` (default 1h)
  whether an annual report is due, then generates it.
- **NAIC adverse-action listener** — polls every `NAIC_POLL_SECONDS` (default 300s).

## Data stores

- **Local state** — SQLite at `SQLITE_PATH` (default `/state/compliance_jobs.sqlite`).
  Schema and idempotent additive migrations live in `app/db.py`.
- **External audit sources** — one or more SQLite databases listed in
  `AUDIT_BUS_DBS`, opened read-only (`immutable=1` / `mode=ro`).
- **Qdrant** — targeted only during DSR erasure, by payload field match
  (`subject_id` / `user_id` / `data_subject_id`).
- **On-disk artifacts** — Merkle root files, archive bundles, DSR confirmations,
  regulatory reports, and signing keys, each under its own directory (see
  [ADMINISTRATOR.md](ADMINISTRATOR.md)).

## Tamper-evidence model

Every regulatory artifact and every Merkle root carries two guarantees:

1. **Integrity** — a SHA-256 hash over the canonical JSON of the payload.
2. **Authenticity** — an Ed25519 signature over the *same* canonical bytes.

Canonical JSON is `json.dumps(payload, sort_keys=True, separators=(",", ":"))`, so
any verifier — in any language — can reproduce the exact signed bytes. The Merkle
roots additionally chain via `parent_root_hash`, and `GET /api/merkle/verify-chain`
walks the chain to detect any break.

## What this repo is *not*

- It does not host or expose the audit trail itself; it consumes external audit
  databases read-only.
- It does not implement the compliance portal or the governance engine that
  *produce* audit events — it reacts to them.
- The enforcement loop in `app/retention.py` implements the SQLite audit-DB
  path. Sources whose backing store is unset or unreachable are skipped
  gracefully.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
