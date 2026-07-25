# bulletproof-compliance-jobs

**Scheduled compliance jobs: data-retention enforcement, DSR cascades, and tamper-evident audit signing.**

![bulletproof-compliance-jobs — overview](docs/media/infographic.png)

`bulletproof-compliance-jobs` runs the background jobs a compliance program needs:
it enforces retention policies, cascades Data Subject Requests (DSR) across data
stores, and produces tamper-evident audit reports using a Merkle-chained, signed
log. It's a FastAPI service backed by SQLite.

> 📚 Full documentation in [`docs/`](docs/) · 🔒 security scan in [`docs/scan/scan-report.md`](docs/scan/scan-report.md) · 🎬 System overview: [briefing](media/system-overview.md) · [video](media/system-overview.mp4).

## What it does

- **Retention** — applies configurable retention policies and purges expired data.
- **DSR cascade** — propagates Data Subject Requests (access/erasure) across the
  relevant records.
- **Merkle audit chain** — hashes audit events into a Merkle chain and signs them,
  so tampering is detectable.
- **Reports** — generates periodic compliance reports.

## Run it

Requires **Python 3.12** (matches the Docker base image; the pinned deps do not
build on newer interpreters).

```bash
pip install -r requirements.txt
cp .env.example .env    # local-run-safe paths; edit to taste
uvicorn app.main:app --env-file .env --host 0.0.0.0 --port 8087
```

Migrations are applied automatically at startup (idempotent, additive — see
`app/db.py`). Or run via Docker (`Dockerfile` included). Storage is SQLite;
all paths and endpoints are configured via env — see `app/config.py`.

### Part of the compliance suite

This service consumes audit databases and cascades DSRs produced/handled by its
sibling projects: [bulletproof-compliance-service](https://github.com/bulletproofsoftware-ai/bulletproof-compliance-service)
(evidence + signing API) and [bulletproof-compliance-portal](https://github.com/bulletproofsoftware-ai/bulletproof-compliance-portal)
(reviewer UI). Each runs standalone; together they form the compliance trio.

## Development

```bash
pip install -r requirements.txt
python -m pytest tests/
```

## License

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
