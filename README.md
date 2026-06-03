# reconmap

[![CI](https://github.com/your-org/reconmap/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/reconmap/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Passive Attack Surface Intelligence Platform** — continuously monitor a domain's subdomains, open ports, and secret leaks by aggregating certificate transparency logs, Shodan, GitHub code search, and DNS resolution. Track changes between scans and generate JSON or dark-theme HTML reports.

---

## Install

### From PyPI (once published)

```bash
pip install reconmap
```

### From source

```bash
git clone https://github.com/your-org/reconmap.git
cd reconmap
pip install -e ".[dev]"
```

### Docker

```bash
docker pull your-org/reconmap:latest
# or build locally
docker build -t reconmap .
```

---

## Quick Start

### Scan a domain

```bash
# Basic scan — JSON output to stdout
reconmap scan example.com

# With API keys
reconmap scan example.com \
  --github-token $GITHUB_TOKEN \
  --shodan-key $SHODAN_API_KEY

# Save HTML report
reconmap scan example.com --output html --out-file report.html

# Save JSON report
reconmap scan example.com --output json --out-file results.json

# Quiet mode (no progress, no tables — only the report)
reconmap scan example.com --quiet
```

### Diff two snapshots

```bash
# Compare the latest two stored snapshots for a domain
reconmap diff example.com --db-url sqlite+aiosqlite:///reconmap.db

# Output as HTML
reconmap diff example.com --output html --out-file diff.html
```

### Start the REST API

```bash
reconmap serve --host 0.0.0.0 --port 8000
```

### Docker Compose

```bash
cp .env.example .env        # set RECONMAP_SHODAN_KEY and RECONMAP_GITHUB_TOKEN
docker compose up
# API available at http://localhost:8000
```

---

## CLI Reference

### `reconmap scan DOMAIN`

Run a passive recon scan against DOMAIN.

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--github-token TEXT` | `RECONMAP_GITHUB_TOKEN` | — | GitHub personal access token for secret scanning |
| `--shodan-key TEXT` | `RECONMAP_SHODAN_KEY` | — | Shodan API key for port/banner data |
| `--output / -o TEXT` | — | `json` | Output format: `json` or `html` |
| `--out-file / -f TEXT` | — | stdout | Write report to this file path |
| `--no-dns` | — | false | Skip DNS brute-force/resolution step |
| `--quiet / -q` | — | false | Suppress progress and summary tables |

Exit code: `1` if any secret leaks were found; `0` otherwise.

### `reconmap diff DOMAIN`

Diff the latest two snapshots stored in the database for DOMAIN.

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--output / -o TEXT` | — | `json` | Output format: `json` or `html` |
| `--out-file / -f TEXT` | — | stdout | Write report to this file path |
| `--db-url TEXT` | `DATABASE_URL` | SQLite `./reconmap.db` | Database connection URL |
| `--quiet / -q` | — | false | Suppress change table output |

Exit code: `1` if any critical or high severity changes were found; `0` otherwise.

### `reconmap serve`

Start the reconmap REST API server.

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--host TEXT` | — | `127.0.0.1` | Bind host |
| `--port INT` | — | `8000` | Bind port |
| `--db-url TEXT` | `DATABASE_URL` | SQLite `./reconmap.db` | Database connection URL |

---

## Python SDK

```python
import asyncio
from reconmap.sdk import ReconMap
from reconmap.reporters import JSONReporter, HTMLReporter

async def main():
    rm = ReconMap(
        shodan_key="YOUR_KEY",
        github_token="YOUR_TOKEN",
        db_url="sqlite+aiosqlite:///./reconmap.db",
    )

    # Run a scan and persist the snapshot
    snapshot = await rm.scan("example.com")
    print(f"Found {len(snapshot.subdomains)} subdomains, {len(snapshot.leaks)} leaks")

    # Diff the two most recent snapshots
    changes = await rm.diff("example.com")
    for change in changes:
        print(f"[{change.severity}] {change.change_type}: {change.asset_key}")

    # Generate reports
    json_reporter = JSONReporter()
    json_reporter.write(snapshot, "report.json")

    html_reporter = HTMLReporter()
    html_reporter.write(snapshot, "report.html", changes=changes)

    await rm.close()

asyncio.run(main())
```

---

## REST API

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check + version |
| `POST` | `/targets` | Register a new target domain |
| `GET` | `/targets` | List all tracked targets |
| `POST` | `/targets/{domain}/scan` | Trigger a passive scan |
| `GET` | `/targets/{domain}/snapshots` | List snapshots (newest first) |
| `GET` | `/targets/{domain}/snapshots/latest` | Get the latest snapshot |
| `GET` | `/targets/{domain}/changes` | List detected changes |

Interactive docs available at `http://localhost:8000/docs`.

---

## Architecture

```
reconmap
├── collectors/          Data-source adapters (passive only)
│   ├── certstream.py    Certificate Transparency logs
│   ├── shodan.py        Shodan Internet-wide scan data
│   ├── github.py        GitHub code search (secret leaks)
│   └── dns_resolver.py  DNS A/AAAA resolution for discovered hosts
│
├── engine/
│   ├── scanner.py       Orchestrates collectors → AssetSnapshot
│   └── diff.py          Diffs two snapshots → list[Change]
│
├── models/
│   └── asset.py         Pydantic models: AssetSnapshot, Change, etc.
│
├── storage/
│   └── db.py            SQLAlchemy async SQLite storage
│
├── reporters/
│   ├── json_reporter.py  JSON serialization
│   └── html.py           Jinja2 dark-theme HTML report
│
├── api/
│   └── app.py           FastAPI REST endpoints
│
├── cli.py               Typer CLI (scan / diff / serve)
└── sdk.py               High-level Python SDK

templates/
└── report.html.j2       Self-contained dark-theme HTML template
```

**Data flow:**

```
User / CI
   │
   ▼
reconmap scan example.com
   │
   ▼
Scanner.run(domain)
   ├──► CertStreamCollector  ──┐
   ├──► ShodanCollector       ├──► AssetSnapshot (merged)
   ├──► GitHubCollector       ┘
   └──► DNSResolverCollector ──► Enrich subdomains with IPs
   │
   ▼
DiffEngine.diff(before, after) ──► list[Change]
   │
   ▼
Storage.save_snapshot()  +  Storage.save_changes()
   │
   ▼
JSONReporter / HTMLReporter ──► report.json / report.html
```

---

## Data Sources

| Source | What it provides | Requires |
|--------|-----------------|---------|
| Certificate Transparency (crt.sh) | Subdomain enumeration | Nothing (public API) |
| Shodan | Open ports, banners, service fingerprints | `RECONMAP_SHODAN_KEY` |
| GitHub Code Search | Secret/credential leaks in public repos | `RECONMAP_GITHUB_TOKEN` |
| DNS Resolver | IP addresses for discovered subdomains | Nothing |

All data collection is **passive** — no active probing or port scanning is performed against the target.

---

## Development Setup

```bash
# Clone and install in editable mode with dev dependencies
git clone https://github.com/your-org/reconmap.git
cd reconmap
pip install -e ".[dev]"

# Run tests
pytest tests/ -q

# Run with coverage
pytest --cov=reconmap --cov-report=term-missing tests/

# Lint (optional)
ruff check src/
mypy src/
```

### Environment variables for integration tests

```bash
export RECONMAP_GITHUB_TOKEN=ghp_...
export RECONMAP_SHODAN_KEY=...
export DATABASE_URL=sqlite+aiosqlite:///./reconmap.db
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
