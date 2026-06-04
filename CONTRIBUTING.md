# Contributing to reconmap

Thanks for your interest in contributing. This document covers how to set up the project, submit changes, and the standards we hold contributions to.

## Development Setup

```bash
git clone https://github.com/dragonday3/reconmap.git
cd reconmap
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest tests/ -q

# With coverage
pytest --cov=reconmap --cov-report=term-missing tests/

# Specific module
pytest tests/test_certstream.py -v
```

All PRs must keep the test suite green across Python 3.10, 3.11, and 3.12.

## Adding a New Collector

1. Create `src/reconmap/collectors/your_source.py` extending `BaseCollector`
2. Implement `async def collect(self, domain: str) -> AssetSnapshot`
3. Set `name` and `requires_key` class attributes
4. Add corresponding tests in `tests/test_your_source.py` (all I/O mocked)
5. Register the collector in `src/reconmap/engine/scanner.py`
6. Document the data source in `README.md`

**Important:** All collectors must be fully passive — no active probing against the target.

## Submitting Changes

1. Fork the repo and create a feature branch: `git checkout -b feat/your-feature`
2. Write tests first (TDD preferred)
3. Keep commits atomic — one logical change per commit
4. Run the full test suite before opening a PR
5. Open a PR against `main` with a clear description of what and why

## PR Requirements

- [ ] Tests pass (`pytest tests/ -q`)
- [ ] New code has test coverage
- [ ] All network/I/O calls are mocked in tests
- [ ] No active probing of targets introduced
- [ ] README updated if behavior changes
- [ ] Commit messages are clear and descriptive

## Reporting Bugs

Open a GitHub issue with:
- Python version and OS
- Minimal reproduction steps
- Expected vs actual behavior
- Full error traceback if applicable

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).
