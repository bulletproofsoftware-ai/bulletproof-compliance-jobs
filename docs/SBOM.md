# Software Bill of Materials — bulletproof-compliance-jobs

A machine-readable CycloneDX 1.6 SBOM is committed at
[`bulletproof-compliance-jobs.cyclonedx.json`](bulletproof-compliance-jobs.cyclonedx.json).
It was generated from the fully resolved install of the pinned
[`requirements.txt`](../requirements.txt) closure (Python 3.12).

- **Format:** CycloneDX 1.6 (JSON)
- **Components:** 45 (the complete transitive dependency graph, including `pip`)
- **Base image:** `python:3.12-slim`

## License distribution

Aggregated across all 45 components (CycloneDX + package metadata). Where a
package declares its license in classifier form, it is grouped with its SPDX
equivalent below.

| License | Approx. count |
|---|---|
| MIT / MIT-0 | 20 |
| BSD (2-/3-Clause) | 17 |
| Apache-2.0 | 7 |
| LGPL-3.0-only (`psycopg`, `psycopg-binary`) | 2 |
| MPL-2.0 (`certifi`) | 2 |
| PSF-2.0 (`typing_extensions`) | 1 |
| Multi-license expressions (`numpy`, `packaging`, `httpx`) | remainder |

All licenses are OSI-approved and permissive except `psycopg`/`psycopg-binary`
(LGPL-3.0). LGPL is satisfied by dynamic linking / normal `pip` install and does
not impose copyleft on this project's own Apache-2.0 code.

## Direct dependencies

These are the packages pinned in `requirements.txt`:

| Package | Version | License | Role |
|---|---|---|---|
| `fastapi` | 0.115.6 | MIT | Web framework / API surface |
| `uvicorn[standard]` | 0.34.0 | BSD-3-Clause | ASGI server |
| `httpx` | 0.28.1 | BSD-3-Clause | Async HTTP client (external Merkle publish) |
| `pyyaml` | 6.0.2 | MIT | YAML parsing |
| `jinja2` | 3.1.6 | BSD-3-Clause | Templating |
| `pydantic` | 2.10.4 | MIT | Request/response models |
| `cryptography` | 48.0.1 | Apache-2.0 / BSD-3-Clause | Crypto primitives |
| `qdrant-client` | 1.12.1 | Apache-2.0 | DSR erasure target client |
| `pynacl` | ≥1.5.0 | Apache-2.0 | Ed25519 signing (libsodium) |
| `psycopg[binary]` | ≥3.2.0 | LGPL-3.0-only | PostgreSQL driver |
| `pytest` | ≥8.0.0 | MIT | Test framework |

`jinja2` and `cryptography` were pinned forward from their initial versions to
clear published advisories — see [scan/scan-report.md](scan/scan-report.md).

## Regenerating the SBOM

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install cyclonedx-bom
cyclonedx-py environment .venv -o docs/bulletproof-compliance-jobs.cyclonedx.json
```

## Base image provenance

The container is built `FROM python:3.12-slim`. Trivy scans the resolved Python
dependency set (not the OS layer in the `standard` profile); the OS layer inherits
Debian's security posture from the upstream `python:3.12-slim` image, which should
be rebuilt periodically to pick up base-image patches.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
