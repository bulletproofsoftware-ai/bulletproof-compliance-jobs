# bulletproof-compliance-jobs

**Scheduled compliance jobs: data-retention enforcement, DSR cascades, and tamper-evident audit signing.**

`bulletproof-compliance-jobs` runs the background jobs a compliance program needs:
it enforces retention policies, cascades Data Subject Requests (DSR) across data
stores, and produces tamper-evident audit reports using a Merkle-chained, signed
log. It's a FastAPI service backed by Postgres.

> 📚 Full documentation in [`docs/`](docs/) · 🔒 security scan in [`docs/scan/scan-report.md`](docs/scan/scan-report.md). (System-overview media coming soon.)

## What it does

- **Retention** — applies configurable retention policies and purges expired data.
- **DSR cascade** — propagates Data Subject Requests (access/erasure) across the
  relevant records.
- **Merkle audit chain** — hashes audit events into a Merkle chain and signs them,
  so tampering is detectable.
- **Reports** — generates periodic compliance reports.

## Run it

```bash
pip install -r requirements.txt
# apply migrations, then:
uvicorn app.main:app --host 0.0.0.0 --port 8087
```

Or via Docker (`Dockerfile` included). Postgres connection is configured via env —
see `app/config.py`.

## Development

```bash
pip install -r requirements.txt
python -m pytest tests/
```

## License

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
