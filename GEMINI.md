# Skywalker - Context & Instructions

## Project Overview

**Skywalker** is a Python-based CLI tool designed for **GCP Audit, Reporting, & Remediation** within UCR Research Computing (specifically for 'Ursa Major' compliance). Its primary function is to "walk" the Google Cloud hierarchy, validate resources against compliance schemas, find wasted spend ("Zombies"), and remediate configuration drift.

### Key Technologies
*   **Language:** Python 3.12+
*   **Packaging:** `uv` (Astral) with `hatchling` backend.
*   **CLI UX:** `rich` for formatting, `argparse` for commands.
*   **Cloud API:** `google-cloud-sdk` (Compute, Storage, Monitoring, Asset, etc.).
*   **Resilience:** `tenacity` for retries.
*   **Architecture:** Centralized `ClientFactory` (`clients.py`) and Modular Modes (`audit`, `monitor`, `fix`, `zombies`).
*   **Validation:** `pydantic` strict models.
*   **Quality:** `ruff` (linting/formatting), `mypy` (strict static typing), `pytest` (testing).

## Project Structure

```text
skywalker/
├── pyproject.toml       # Dependencies (google-cloud-*, rich, tenacity, weasyprint)
├── uv.lock              # Lock file
├── README.md
├── src/
│   └── skywalker/
│       ├── __init__.py
│       ├── main.py      # CLI Entry Point & Dispatcher
│       ├── clients.py   # Centralized GCP Client Factory (LRU Cached)
│       ├── logger.py    # Rich Logger Configuration
│       ├── modes/
│       │   ├── audit.py    # Audit Mode Logic
│       │   ├── monitor.py  # Fleet Performance Mode
│       │   ├── fix.py      # Remediation Mode (Ops Agent)
│       │   └── zombies.py  # Zombie Hunter Mode (Cost Optimization)
│       ├── schemas/     # Pydantic Models (compute, storage, etc.)
│       └── walkers/     # API Interaction Logic (compute.py, network.py, etc.)
├── tests/
│   └── ...              # Pytest suite
└── .github/
    └── workflows/
        └── test.yml     # CI/CD: Lint, Type-Check, Test
```

## Operational Rules (Memory Bank)

1.  **Workflow:** Always use **Feature Branches** -> **Pull Requests** -> **Merge**. Never commit to `master` directly.
2.  **Versioning:** Every functional code change requires a version bump in `pyproject.toml`.
3.  **Code Quality:**
    *   No placeholders. Write complete code.
    *   Strict typing (`mypy strict`).
    *   All imports must be sorted (`ruff check --select I`).
4.  **Testing:**
    *   Use `pytest-mock` to mock GCP API calls.
    *   Mock `subprocess.run` for remediation tests.
5.  **Safety:**
    *   **Remediation:** Must be interactive (`Confirm.ask`) and scoped.
    *   **Secrets:** Never output secrets.
6.  **Performance:**
    *   Use `ThreadPoolExecutor` for multi-project scans.
    *   **No Caching:** `joblib` has been removed. Always fetch fresh data.

## Current State (as of Dec 23, 2025)

*   **Version:** 0.32.0
*   **Capabilities:**
    *   **Audit:** Scans 9+ services across 150+ projects.
    *   **Monitor:** Real-time fleet dashboard (CPU/Mem/GPU).
    *   **Zombie Hunter:** Finds Orphaned Disks, Unused IPs, Inactive Buckets.
    *   **Fix-It:** Auto-installs Ops Agent via SSH/IAP.
*   **Architecture:** Fully modularized `main.py` and centralized clients.