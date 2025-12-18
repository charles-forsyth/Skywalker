# Skywalker - Context & Instructions

## Project Overview

**Skywalker** is a Python-based CLI tool designed for **GCP Audit & Reporting** within UCR Research Computing (specifically for 'Ursa Major' compliance). Its primary function is to "walk" the Google Cloud hierarchy, validate resources against compliance schemas, and generate reports.

### Key Technologies
*   **Language:** Python 3.10+
*   **Packaging:** `uv` (Astral) with `hatchling` backend.
*   **CLI UX:** `rich` for formatting, `argparse` for commands.
*   **Cloud API:** `google-cloud-sdk` (Compute, Storage, Resource Manager).
*   **Resilience:** `tenacity` for retries.
*   **Caching:** `joblib` for local development speed.
*   **Validation:** `pydantic` strict models.
*   **Quality:** `ruff` (linting/formatting), `mypy` (strict static typing), `pytest` (testing).

## Project Structure

```text
skywalker/
├── pyproject.toml       # Project configuration, dependencies, tools (ruff, mypy)
├── uv.lock              # Lock file for reproducible builds
├── README.md
├── src/
│   └── skywalker/
│       ├── __init__.py
│       ├── main.py      # CLI Entry point
│       ├── models.py    # Pydantic data schemas
│       └── walker.py    # Core logic (GCP API calls, caching, retries)
├── tests/
│   ├── __init__.py
│   └── test_walker.py   # Unit tests with mocks
└── .github/
    └── workflows/
        └── test.yml     # CI/CD: Lint, Type-Check, Test
```

## Development & Usage

### Installation

This project is optimized for `uv`.

```bash
# Install tool globally
uv tool install .

# Install dependencies in a venv for development
uv sync --extra dev --extra test
```

### Running the Tool

```bash
# Run via uv (dev mode)
uv run skywalker --project-id <PROJECT_ID> --zone <ZONE>

# Run installed tool
skywalker --project-id ucr-research-computing --zone us-central1-a
```

### Testing & Quality Assurance

All features **must** pass these checks before merging.

```bash
# Run Unit Tests
uv run --extra test pytest

# Run Linter (Ruff)
uv run --extra dev ruff check .

# Run Formatter (Ruff)
uv run --extra dev ruff format .

# Run Type Checker (Mypy)
uv run --extra dev mypy src
```

## Operational Rules (Memory Bank)

1.  **Workflow:** Always use **Feature Branches** -> **Pull Requests** -> **Merge**. Never commit to `master` directly.
2.  **Versioning:** Every functional code change requires a version bump in `pyproject.toml` to ensure `uv tool update` works for users.
3.  **Code Quality:**
    *   No placeholders. Write complete code.
    *   Strict typing is enforced (`mypy strict`).
    *   All imports must be sorted (`ruff check --fix`).
4.  **Testing:**
    *   Use `pytest-mock` to mock GCP API calls.
    *   Use the `clear_cache` fixture (in `tests/test_walker.py` or `conftest.py`) to prevent `joblib` from interfering with tests.
5.  **Safety:**
    *   Never output secrets.
    *   Read-only operations by default unless explicitly authorized.

## Current State (as of Dec 18, 2025)

*   **Version:** 0.1.0
*   **Capabilities:** Can list Compute Instances in a specific zone.
*   **Next Steps:** Refactoring to a Modular Architecture (Compute, Storage, GKE, etc.) and implementing Deep Compute inspection.
