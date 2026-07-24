# How to Use — bulletproof-compliance-jobs

This is a task-oriented guide to the HTTP API. All examples assume the service is
running on `http://localhost:8087`. Responses are JSON.

The API surface is defined in `app/main.py`. There is no built-in authentication;
run the service behind your own network policy.

## Health & dashboard

```bash
# Liveness + active components + configured audit DBs
curl -s http://localhost:8087/health

# Aggregate operational snapshot
curl -s http://localhost:8087/api/dashboard
```

`/api/dashboard` returns the Merkle chain status, recent roots, recent retention
runs, active legal holds, pending DSRs, and recent report runs in one call.

## Merkle audit chain

```bash
# Force-publish a root for the current window (normally hourly & automatic)
curl -s -X POST http://localhost:8087/api/merkle/publish-now

# List recent roots (default 50, max 500)
curl -s "http://localhost:8087/api/merkle/roots?limit=20"

# Verify the whole chain — walks parent_root_hash links
curl -s http://localhost:8087/api/merkle/verify-chain
```

`verify-chain` returns `{"total_roots": N, "breaks": [...], "intact": true|false}`.
Any non-empty `breaks` array means a root's `parent_root_hash` did not match the
previous root — investigate immediately.

## Retention

```bash
# Run a retention sweep now (archive past-horizon records, delete on RW mounts)
curl -s -X POST http://localhost:8087/api/retention/run-now

# History of sweeps
curl -s "http://localhost:8087/api/retention/runs?limit=30"
```

### Legal holds

A legal hold pauses deletion for a given session id. Held records are still
archived but never deleted while the hold is active.

```bash
# Place a hold
curl -s -X POST http://localhost:8087/api/retention/holds \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"session-123","reason":"litigation X","placed_by":"legal-ops"}'

# List active holds
curl -s "http://localhost:8087/api/retention/holds?active_only=true"

# Release a hold (use the hold_id returned when placing it)
curl -s -X DELETE http://localhost:8087/api/retention/holds/<hold_id>
```

## DSR cascade (GDPR)

```bash
# 1. Submit a request (returns a request_id and a 30-day deadline)
curl -s -X POST http://localhost:8087/api/dsr/submit \
  -H 'Content-Type: application/json' \
  -d '{"subject_id":"subj-42","request_type":"erasure","subject_email":"person@example.com"}'

# 2. Execute the erasure cascade for that request
curl -s -X POST http://localhost:8087/api/dsr/<request_id>/execute

# List DSR requests (optionally by status)
curl -s "http://localhost:8087/api/dsr/requests?status=received&limit=50"
```

`request_type` accepts `erasure | access | rectification | restriction |
portability | objection`. The erasure cascade:

1. Purges Qdrant points matching the subject (`subject_id` / `user_id` /
   `data_subject_id` payload fields).
2. Deletes subject-tagged evidence files.
3. **Counts** (does not delete) audit-trail references — the audit trail is
   immutable; the deletion event is itself recorded.
4. Writes a signed deletion-confirmation artifact under
   `DSR_DELETION_CONFIRMATION_DIR`, whose path is returned in the response.

## Regulatory reports

Supported `report_type` values: `sox_attestation`, `nydfs_part500`, `eu_ai_act`,
`naic_adverse_action`.

```bash
# Generate a report for an explicit period
curl -s -X POST http://localhost:8087/api/reports/generate \
  -H 'Content-Type: application/json' \
  -d '{"report_type":"sox_attestation","period_start":"2025-01-01T00:00:00+00:00","period_end":"2025-12-31T23:59:59+00:00"}'

# Fire all annual reports for a year (default: previous calendar year)
curl -s -X POST "http://localhost:8087/api/reports/annual?year=2025"

# List generated reports
curl -s "http://localhost:8087/api/reports/runs?limit=50"
```

Each report is a signed JSON evidence package written to `REPORTS_DIR`. The
response includes `artifact_path`, `artifact_sha256`, and the embedded
`signature`.

### Annual scheduler

```bash
# Force one annual report regardless of schedule
curl -s -X POST http://localhost:8087/annual/run-now \
  -H 'Content-Type: application/json' \
  -d '{"report_type":"nydfs_part500","year":2025}'

# Inspect the schedule: due-ness, last run, next check time per report type
curl -s http://localhost:8087/annual/schedule
```

`/annual/run-now` also accepts `naic_adverse_action_consolidated` for a
consolidated annual NAIC report. `year` must be between 1970 and 2200.

## NAIC adverse-action artifacts

```bash
# Trigger a scan iteration now (operator/test path)
curl -s -X POST http://localhost:8087/naic/scan-now

# List artifacts detected in a lookback window (1–3650 days)
curl -s "http://localhost:8087/naic/recent?days=30"
```

A scan reads the audit DBs for adverse-action events (policy denials, threat
detections, guardian actions at high/critical severity) and generates one NAIC
artifact per **new** event. Re-running is safe — already-processed events are
skipped (`skipped_already_tracked`).

## Cryptographic signing & verification

Every signed artifact carries a SHA-256 integrity hash and an Ed25519 signature
over the same canonical JSON.

```bash
# Fetch the current public key (hex, base64, key_id). Never exposes the private key.
curl -s http://localhost:8087/signing/public-key

# Verify a signature against the exact canonical-JSON bytes that were signed
curl -s -X POST http://localhost:8087/signing/verify \
  -H 'Content-Type: application/json' \
  -d '{
        "payload_canonical_json": "<exact signed bytes as UTF-8 string>",
        "signature_hex": "<hex signature>",
        "key_id": "<16-char key id>"
      }'
```

`verify` resolves `key_id` against the current key and any rotated key under
`signing-keys/archive/`, so artifacts signed by an older key remain verifiable.
It returns `valid`, `key_matches`, and the `resolved_public_key`.

### Reproducing canonical JSON

To verify an artifact yourself, strip the `signature` and `artifact_sha256`
fields, then re-serialise with:

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
```

This is byte-for-byte identical to what the service signed.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
