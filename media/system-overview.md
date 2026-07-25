# Technical Briefing: bulletproof-compliance-jobs

## 1. System Introduction and Core Purpose
`bulletproof-compliance-jobs` is a specialized FastAPI service architected to automate the recurring background tasks required by modern compliance programs. Its primary mission is the enforcement of data-retention policies, the execution of cascading Data Subject Requests (DSR) across distributed environments, and the generation of cryptographically signed, tamper-evident audit evidence.

The service operates as a secondary, non-destructive layer over the existing infrastructure. It maintains a strictly read-only relationship with external audit sources—consuming databases to hash, archive, and sign data—without ever mutating the original source-of-truth audit trail. All operational state, including Merkle chain history and cryptographic material, is managed within a self-contained local environment.

## 2. Core Architectural Components

### Automated Schedulers
The system initializes four primary asyncio schedulers during the service lifespan to manage background operations:

| Scheduler Name | Functionality | Default Interval/Cadence |
| :--- | :--- | :--- |
| **Merkle publisher** | Scans external audit databases to hash events into leaves, builds and signs a Merkle root, and generates immutable JSON artifacts. | Hourly (fired a few minutes past the hour) |
| **Retention enforcer** | Archives past-horizon records to compressed JSONL; executes deletion on RW mounts while shielding records under legal hold. | Every 24 hours (`RETENTION_INTERVAL_HOURS`) |
| **Annual report scheduler** | Evaluates and generates pending annual regulatory reports (SOX, NY DFS Part 500, EU AI Act, NAIC). | Every 1 hour (`ANNUAL_CHECK_HOURS`) |
| **NAIC adverse-action listener** | Polls audit DBs for adverse-action events (policy denials, threat detections) and generates idempotent NAIC artifacts. | Every 300 seconds (`NAIC_POLL_SECONDS`) |

### Technology Stack
*   **Runtime:** Python 3.12 (utilizing the `python:3.12-slim` base image).
*   **Framework:** FastAPI for HTTP API surface and lifecycle management.
*   **State Management:** A local SQLite database manages operational history, migrations, and tracking.
*   **External Integration:** Support for Postgres and n8n retention classes via `psycopg[binary]`.
*   **Cryptography:** PyNaCl (libsodium) for Ed25519 signing and verification.

## 3. Data Infrastructure and Storage Layout

### /state Directory Structure
The `/state` directory must be a persistent volume. The system enforces the following subdirectory mapping for artifacts:
*   **/merkle-roots:** Storage for immutable JSON files representing each hourly Merkle root.
*   **/archive:** Compressed `JSONL.gz` bundles containing data past the retention horizon.
*   **/signing-keys:** Ed25519 key material and an `archive/` subfolder for rotated keys.
*   **/legal-holds:** Working directory for session-specific legal-hold data.
*   **/dsr-confirmations:** Signed proofs of DSR erasure/access execution.
*   **/regulatory-reports:** Signed artifacts for regulatory reporting (SOX, NAIC, etc.).

### Read-Only Audit Mounts Strategy
To prevent accidental mutation of the audit trail, external databases should be mounted as read-only. The service utilizes a non-destructive probe to determine mount capabilities: it attempts a `BEGIN IMMEDIATE` sequence followed by a `CREATE TEMP TABLE` and a `ROLLBACK`.
*   **RW Mount:** The system performs full retention (archives followed by deletion).
*   **RO Mount:** The system enters **archive-only mode**. It opens the database using `immutable=1` or `mode=ro` to prevent SQLite from attempting to create WAL or journal files on read-only media. In this mode, deletion is skipped and reported as `cannot_delete=true`.

### Local SQLite Schema
The state database (`compliance_jobs.sqlite`) manages idempotent tracking via the following tables:
*   `merkle_roots`: Sequence-numbered, chained, and signed hourly roots.
*   `retention_runs`: Logs of retention sweeps with per-class object counts.
*   `legal_holds`: Records of active/released holds that pause data deletion.
*   `dsr_cascades`: Log of DSR requests and subsystem-specific deletion counts.
*   `regulatory_runs`: Metadata for generated reports, including associated signing key IDs.
*   `naic_actions`: Idempotent tracking to ensure adverse-action events are only processed once.

## 4. Tamper-Evidence and Cryptographic Model

### Two-Pillar Integrity Model
The service ensures artifact validity through two distinct cryptographic pillars:
1.  **SHA-256 Integrity:** A cryptographic hash generated over the canonical JSON payload.
2.  **Ed25519 Authenticity:** A digital signature produced over the same canonical bytes to verify the service as the source.

### Canonical JSON Requirements
To ensure verifiability across diverse environments, all signatures are generated using Canonical JSON. This requires serializing data with sorted keys and specific separators to ensure byte-for-byte identity:
`json.dumps(payload, sort_keys=True, separators=(",", ":"))`

### Merkle Audit Chain Process
The system maintains a continuous chain of audit events. Every hour, events are hashed into the leaves of a Merkle tree. The resulting root is signed and includes a `parent_root_hash`, chaining the current root to its predecessor. This structure allows the `/api/merkle/verify-chain` endpoint to walk the history and detect unauthorized modifications or structural breaks.

### Signing-Key Lifecycle & Rotation
*   **Generation:** A keypair is automatically generated on first start. The `key_id` (a 16-hex prefix of the public key) is logged once; the private key is never logged.
*   **Rotation:** Operators rotate keys by moving current files into `signing-keys/archive/<key_id>/`. The service generates a new pair on restart.
*   **Verifiability:** The service resolves the `key_id` against both the current key and the archive, ensuring historical artifacts remain verifiable post-rotation.

## 5. Functional Workflows and API Usage

### DSR Cascades (GDPR)
When an erasure request is initiated, the service executes a four-step cascade:
1.  **Qdrant Purge:** Points matching the subject ID are purged from vector collections.
2.  **Evidence Deletion:** Subject-tagged files in local evidence storage are deleted.
3.  **Audit Trail Handling:** The system counts references in the audit trail but does not delete them, as the trail is immutable.
4.  **Logging & Artifacts:** The **erasure event itself is recorded** in the audit trail to maintain a complete log of compliance actions. A signed deletion-confirmation artifact is then generated.

### Retention Enforcement
The retention loop evaluates data against `AUDIT_RETENTION_YEARS` and `EVIDENCE_RETENTION_YEARS`. If a **Legal Hold** is active for a session ID, associated records are archived but shielded from deletion.

### Regulatory Reporting
The service supports several `report_type` values, generating signed JSON evidence packages:
*   `sox_attestation`
*   `nydfs_part500`
*   `eu_ai_act`
*   `naic_adverse_action` (including the annual `naic_adverse_action_consolidated`).

### Verifying the Chain
The integrity of the Merkle log is verified via `/api/merkle/verify-chain`. A non-empty `breaks` array indicates a mismatch between a root's `parent_root_hash` and the preceding root, signaling a compromise of the audit history.

## 6. Configuration Reference

| Environment Variable | Default Value | Operational Purpose |
| :--- | :--- | :--- |
| `SQLITE_PATH` | `/state/compliance_jobs.sqlite` | Path to the local operational state database. |
| `AUDIT_BUS_DBS` | `/governance/audit.db,...` | Comma-separated external audit sources (mounted RO). |
| `SIGNING_KEY_DIR` | `/state/signing-keys` | Directory for Ed25519 keys and archives. |
| `MERKLE_ROOTS_DIR` | `/state/merkle-roots` | Storage for immutable per-root JSON files. |
| `ARCHIVE_DIR` | `/state/archive` | Directory for compressed retention archives. |
| `LEGAL_HOLD_DIR` | `/state/legal-holds` | Working directory for active legal holds. |
| `DSR_DELETION_CONFIRMATION_DIR` | `/state/dsr-confirmations` | Storage for signed DSR deletion proofs. |
| `REPORTS_DIR` | `/state/regulatory-reports` | Storage for signed regulatory report artifacts. |
| `AUDIT_RETENTION_YEARS` | `7` | Retention horizon for audit data. |
| `EVIDENCE_RETENTION_YEARS` | `7` | Retention horizon for evidence artifacts. |
| `RETENTION_INTERVAL_HOURS` | `24` | Frequency of the retention sweep. |
| `ANNUAL_CHECK_HOURS` | `1` | Frequency for annual report due-checks. |
| `NAIC_POLL_SECONDS` | `300` | Polling interval for new NAIC events. |
| `QDRANT_URL` | `http://qdrant:6333` | Erasure target; if unset, purge acts as a graceful no-op. |

## 7. Security and Operational Posture

1.  **Unprivileged Execution:** The service runs as `appuser` (uid 10001) to limit the blast radius of potential vulnerabilities.
2.  **Network Isolation:** No internal authentication is provided; the service must be deployed behind a network gateway or internal policy.
3.  **Key Protection:** The private key is never logged and is stored with restrictive permissions (0600).
4.  **Self-Healing Pubkeys:** Public key files will automatically regenerate from the private key if deleted.
5.  **Graceful Degradation:** If `QDRANT_URL` is unset or unreachable, the DSR purge operation fails gracefully (no-op) to prevent service disruption.
6.  **Read-Only Integrity:** The use of `immutable=1` and `mode=ro` for audit database connections ensures the service cannot create temporary files or journals on read-only media.

**CRITICAL DATA PERSISTENCE WARNING:**
The `/state` volume must be persisted. Loss of this directory results in the permanent loss of signing keys—rendering all previous artifacts unverifiable—and the destruction of the Merkle chain history.