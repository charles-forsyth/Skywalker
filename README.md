# Skywalker

**Skywalker** is the official GCP Audit & Reporting Tool for **UCR Research Computing**. It provides deep visibility into the "Ursa Major" research fleet, helping administrators detect security risks, optimize costs, and maintain operational hygiene across hundreds of Google Cloud projects.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-CLI%20%2B%20MCP%20Pilot-blue)

## 🚀 Key Capabilities

### 1. 🔍 Deep Audit
Scans a specific project or the entire organization for resources across **9 GCP Services**:
*   **Compute Engine:** VMs, Disks, Images, Snapshots (with GPU & Utilization metrics).
*   **Storage:** Buckets, Sizes, Public Access Prevention status.
*   **IAM:** Service Accounts, Keys, and Privileged Roles (Owner/Editor/Viewer).
*   **Network:** Firewalls (Open Ports), Static IPs, VPCs.
*   **Kubernetes (GKE):** Clusters, Node Pools, Versions.
*   **Cloud Run:** Services, Images, Last Modifiers.
*   **Cloud SQL & Filestore:** Databases and NFS shares.
*   **Vertex AI:** Notebooks and Endpoints.

### 2. 📊 Fleet Performance Monitoring
Aggregates real-time metrics (CPU, Memory, GPU) from hundreds of VMs into a single "Mission Control" dashboard.
*   Identifies "noisy neighbors" and overloaded instances.
*   Detects "Blind Spots" (VMs missing the Ops Agent).

### 3. 🧟 Zombie Hunter
**Finds and quantifies wasted spend.** Scans the entire organization for:
*   **Orphaned Disks:** Unattached persistent disks silently charging monthly fees.
*   **Unused Static IPs:** Reserved external IPs not attached to any resource.
*   **Inactive Buckets:** GCS buckets with zero egress activity for 30 days.
*   **Calculates ROI:** Estimates potential monthly savings from list-price disk and IP rates.

### 4. 🛠️ Automated Remediation
Interactive "Fix-It" mode to solve common fleet issues at scale.
*   **Ops Agent Installer:** Mass-deploys the Google Cloud Ops Agent to Linux VMs via SSH (IAP Tunneling) to fix monitoring blind spots.

### 5. 🤖 Model Usage & Cost Tracking
Tracks and aggregates generative model usage (Vertex AI, Publisher Models) across individual projects or the entire fleet:
*   **Official Metrics:** Directly queries Cloud Monitoring timeseries for request count (`online_serving/model_invocation_count`) and input/output token counts (`online_serving/token_count`).
*   **Pricing Map:** Dynamically parses model prices from `model_prices.csv` to calculate accurate estimated spend.
*   **Fleet-Wide Summaries:** Aggregates costs, requests, and tokens, sortable by estimated cost or project ID, with full detailed nested tabular breakdowns.

### 6. 🔌 Hosted MCP Server (`mcp_server/`)
Exposes 21 strictly read-only Google Cloud tools (`skywalker.intel`) over Streamable HTTP (`/mcp`):
*   **Caller-Scoped GCP Access & Atrium Brokered Assertions:** OAuth 2.1 + PKCE S256 (`POST /authorize` consent confirmation, grant-family refresh rotation, pinned `SKYWALKER_PUBLIC_URL`) plus short-lived `atr1.*` ECDSA P-256 Atrium brokered assertions (`ATRIUM_BROKER_PUBKEY`, fail-closed, `exp - iat <= 360`, pre-registered `program_client` role ceiling and rate limits). Every tool reads Google Cloud with the signed-in caller's own OAuth token, while the server's service account holds zero GCP data roles. External A2A lives exclusively on Atrium Concierge.
*   **Per-Researcher Scope & Allocation Fallback:** `read` callers are restricted to their listed `projects` in `users.yaml` and receive scoped monthly allocation/usage summaries (`project_allocations` + optional `SKYWALKER_PROJECT_USAGE_FILE`) when central Cloud Billing IAM is unavailable.
*   **Full Specification & Setup:** See [`mcp_server/README.md`](mcp_server/README.md) and [`docs/SPEC.md`](docs/SPEC.md).

## 📦 Installation

Skywalker is packaged with `uv` for speed and isolation.

```bash
# Install tool globally
uv tool install . --force
```

## 🛠️ Usage

### Standard Audit
Audit a single project for all services.
```bash
skywalker --project-id ucr-research-computing
```

Audit specific services in specific regions.
```bash
skywalker --project-id my-lab-project --services compute storage --regions us-west1
```

### Model Usage & Cost Audit 🤖
Audit official Vertex AI/Publisher model consumption and costs over a given time window (defaults to 30 days) for a single project or fleet-wide.
```bash
# Audit a single project
skywalker --project-id ucr-research-computing --model-audit --days 30

# Run fleet-wide and sort projects by estimated cost
skywalker --all-projects --model-audit --sort-by estimated_cost

# Get a structured JSON output of all models and metrics
skywalker --all-projects --model-audit --json
```

### Zombie Hunting 🧟
Find wasted resources across ALL projects in the org.
```bash
skywalker --find-zombies
```

### Fleet Monitoring
View a live dashboard of top CPU/Memory consumers.
```bash
skywalker --monitor --limit 20
```

### Remediation (Fix-It)
Install Ops Agent on all VMs in the monitoring scope that are missing it.
```bash
skywalker --fix ops-agent --monitor
```

### Reporting
Generate a PDF or HTML report for stakeholders.
```bash
skywalker --all-projects --html fleet_report.html
```

## 🏗️ Architecture

*   **Language:** Python 3.12+
*   **Core:** `google-cloud-sdk` (Official Python Clients).
*   **Concurrency:** `ThreadPoolExecutor` for high-speed parallel scanning of 100+ projects.
*   **Design:** Modular "Walkers" for each service, centralized client management, and strict Pydantic schemas.
*   **Safety:** Read-only by default (except `--fix`). Interactive confirmation required for changes.

## 🤝 Contributing

1.  Create a feature branch (`feat/new-thing`).
2.  Write CLI and MCP tests (`pytest` and `bash scripts/test_mcp.sh`).
3.  Verify security mutation guards (`python3 scripts/mcp_mutation_check.py`).
4.  Ensure typing and formatting pass (`mypy src` and `ruff check .`).
5.  Submit a PR.

---
*Maintained by Charles Forsyth (UCR Research Computing)*
