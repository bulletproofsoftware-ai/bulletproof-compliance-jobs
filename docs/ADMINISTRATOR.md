# Administrator Guide — bulletproof-compliance-jobs

This guide covers operating the service: configuration, the on-disk layout, the
schedulers, signing-key lifecycle, and day-to-day operational tasks. It assumes
you have read [OVERVIEW.md](OVERVIEW.md).

## Full configuration reference

All settings are environment variables read in `app/config.py`. Paths default to
subdirectories of `/state`, which should be a persistent volume.

### Storage & audit sources

| Env var | Default | Notes |
|---|---|---|
| `SQLITE_PATH` | `/state/compliance_jobs.sqlite` | Local operational state DB |
| `AUDIT_BUS_DBS` | `/governance/audit.db,/security/audit_bus.sqlite` | Comma-separated list of external audit DBs, mounted **read-only** |
| `MERKLE_ROOTS_DIR` | `/state/merkle-roots` | One immutable JSON file per Merkle root |
| `ARCHIVE_DIR` | `/state/archive` | Compressed JSONL.gz retention archives |
| `LEGAL_HOLD_DIR` | `/state/legal-holds` | Legal-hold working directory |
| `DSR_DELETION_CONFIRMATION_DIR` | `/state/dsr-confirmations` | Signed DSR deletion proofs |
| `REPORTS_DIR` | `/state/regulatory-reports` | Signed regulatory report artifacts |
| `SIGNING_KEY_DIR` | `/state/signing-keys` | Ed25519 key material + `archive/` for rotated keys |

### Retention

| Env var | Default | Notes |
|---|---|---|
| `AUDIT_RETENTION_YEARS` | `7` | Horizon for audit data |
| `EVIDENCE_RETENTION_YEARS` | `7` | Horizon for evidence artifacts |
| `RETENTION_INTERVAL_HOURS` | `24` | Sweep cadence |

### DSR cascade

| Env var | Default | Notes |
|---|---|---|
| `QDRANT_URL` | `http://qdrant:6333` | Erasure target; if unset/unreachable, Qdrant purge is a no-op |
| `QDRANT_API_KEY` | *(empty)* | Optional Qdrant auth |
| `COMPLIANCE_PORTAL_URL` | `http://compliance-portal-internal:8001` | Reserved for portal integration |
| `COMPLIANCE_API_TOKEN` | *(empty)* | Reserved |

### Reports & signing

| Env var | Default | Notes |
|---|---|---|
| `REPORT_OPERATOR_ID` | `compliance-jobs-system` | Recorded as the operator on each report |
| `ANNUAL_CHECK_HOURS` | `1` | How often the annual scheduler evaluates due-ness |
| `NAIC_POLL_SECONDS` | `300` | Adverse-action poll interval |
| `MERKLE_INTERVAL_MINUTES` | `60` | Informational; the loop fires hourly |
| `MERKLE_PUBLISH_URL` | *(empty)* | Optional external write-once endpoint |
| `MERKLE_PUBLISH_TOKEN` | *(empty)* | Bearer token for the endpoint above |

### Server

| Env var | Default |
|---|---|
| `HOST` | `0.0.0.0` |
| `PORT` | `8087` |

## On-disk layout (`/state`)

```
/state/
├── compliance_jobs.sqlite       # operational state (see schema below)
├── merkle-roots/
│   └── merkle-00000001.json     # one write-once file per root (chmod 0444)
├── archive/
│   └── audit-<db>-<ts>.jsonl.gz # compressed retention archives (chmod 0444)
├── legal-holds/
├── dsr-confirmations/
│   └── dsr-<request_id>.json     # signed deletion proof (chmod 0444)
├── regulatory-reports/
│   └── <report_type>-<uuid>.json # signed report (chmod 0444)
└── signing-keys/
    ├── ed25519_private.key       # raw 32-byte seed (chmod 0600)
    ├── ed25519_public.key.hex
    ├── ed25519_public.key.b64
    ├── current_key_id
    └── archive/<key_id>/…         # rotated keys, for verification fallback
```

Artifacts are written with restrictive permissions where the OS honours it
(`0444` for evidence/roots, `0600` for the private key).

## Local SQLite schema

Created and migrated automatically on start (`app/db.py`). Tables:

- `merkle_roots` — sequence-numbered, chained, signed hourly roots.
- `retention_runs` — history of retention sweeps, with per-class counts.
- `legal_holds` — active/released holds that pause deletion.
- `dsr_cascades` — DSR request log with per-subsystem deletion counts.
- `regulatory_runs` — generated report metadata + signing key id.
- `naic_actions` — one idempotent row per processed adverse-action event.

## Schedulers

Started in `app/main.py:lifespan`, cancelled cleanly on shutdown:

1. **Merkle publisher** (`_merkle_loop`) — wakes a few minutes past the hour,
   reads the prior hour's audit events across `AUDIT_BUS_DBS`, builds and signs a
   root, writes the immutable file, and optionally POSTs to `MERKLE_PUBLISH_URL`.
2. **Retention enforcer** (`_retention_loop`) — every `RETENTION_INTERVAL_HOURS`,
   archives past-horizon records then deletes them (RW mounts only).
3. **Annual report scheduler** (`_annual_report_loop`) — every `ANNUAL_CHECK_HOURS`,
   generates any annual report (SOX, NY DFS Part 500, EU AI Act) not yet on file
   for the previous calendar year.
4. **NAIC adverse-action listener** (`_naic_adverse_action_loop`) — every
   `NAIC_POLL_SECONDS`, scans the audit DBs for adverse-action events and
   generates one NAIC artifact per new event (idempotent).

## Read-only audit mounts

The retention enforcer probes each audit DB for write access using a
non-destructive `BEGIN IMMEDIATE` + `CREATE TEMP TABLE` + `ROLLBACK` sequence
(`app/retention.py:_connect_audit_db`). If the mount is read-only, it:

- opens the DB with `immutable=1` (so SQLite never tries to create WAL/journal),
- **archives** past-horizon records to JSONL.gz, and
- **skips** deletion, reporting `cannot_delete=true` / `ro_mount=true`.

This is the recommended production posture: mount audit DBs `:ro` and rotate the
source out of band once archives cover the horizon.

## Signing-key lifecycle & rotation

- On first start, a keypair is generated and the `key_id` (16-hex prefix of the
  public key) is logged **once**. The private key is never logged.
- Public key files self-heal if deleted while the private key remains.
- **Rotation**: move the current key files into
  `signing-keys/archive/<key_id>/`, remove the top-level files, and restart. A new
  keypair is minted, and `POST /signing/verify` still resolves the archived key by
  its `key_id`, so historical artifacts remain verifiable.

**Back up `SIGNING_KEY_DIR` and `/state`.** Losing the signing key breaks
verification of every previously signed artifact; losing the SQLite DB breaks the
Merkle chain history.

## Operational checks

```bash
# Health + configured audit DBs
curl -s http://localhost:8087/health | python3 -m json.tool

# Verify the Merkle chain has no breaks
curl -s http://localhost:8087/api/merkle/verify-chain | python3 -m json.tool

# Aggregate ops dashboard
curl -s http://localhost:8087/api/dashboard | python3 -m json.tool

# Annual report schedule / due-ness
curl -s http://localhost:8087/annual/schedule | python3 -m json.tool
```

## Security notes

- The container runs as unprivileged `appuser` (uid 10001).
- Audit databases should be mounted read-only.
- The service exposes no authentication of its own; place it behind your
  network policy / gateway. The optional external Merkle endpoint is the only
  outbound call and uses a bearer token if configured.
- Dependency posture is tracked in [SBOM.md](SBOM.md); the latest security scan
  is in [scan/scan-report.md](scan/scan-report.md).

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
