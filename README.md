# Skywalker 🚀

**GCP Ursa Major Audit Tool for UCR Research Computing**

Skywalker is a high-performance CLI tool designed to "walk" the Google Cloud Platform (GCP) hierarchy to audit resources, validate security compliance (Ursa Major standards), and generate professional reports.

## Features

- **Ursa Major Auditor:** Automatically discovers and audits ALL active projects in your organization/folder.
- **Deep Inspection:** 
    - **Compute Engine:** VMs, Disks, GPUs, IPs.
    - **Cloud Storage:** Bucket sizes (via Monitoring), Public Access Prevention (PAP).
    - **Cloud Run:** Serverless services and revisions.
    - **GKE:** Clusters and Node Pools.
    - **Cloud SQL:** Database instances, versions, and public IP exposure.
    - **Vertex AI:** Notebooks, Models, and Endpoints.
    - **IAM:** Service Accounts, Keys, and High-Privilege Role analysis.
    - **Network:** Firewall rules (flagging `0.0.0.0/0`) and Static IPs.
- **Parallel Execution:** 
    - Scans multiple projects concurrently.
    - Scans multiple regions concurrently within each project.
- **Reporting:** 
    - **Console:** Rich, color-coded terminal output.
    - **JSON:** Pipeable, structured data for all projects.
    - **PDF/HTML:** Professional compliance reports with executive summaries.

## Prerequisites

### 1. Authentication
Skywalker uses Google Cloud Application Default Credentials (ADC).

```bash
gcloud auth login
gcloud auth application-default login
```

### 2. PDF Rendering (Optional)
If you intend to use `--report` (PDF), your system must have `pango` and `cairo` installed.

**Ubuntu/Debian:**
```bash
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

**macOS:**
```bash
brew install pango
```

### 3. Usage

#### 🔍 Basic Audit (Single Project)
```bash
# Basic scan (outputs to terminal)
skywalker --project-id ucr-research-computing

# Audit specific services only (e.g., just IAM and Storage)
skywalker --project-id ucr-research-computing --services iam storage

# Audit all services (explicitly)
skywalker --project-id ucr-research-computing --services all
```

#### 🚀 Ursa Major Audit (Multi-Project)
Automatically discover and scan all active projects you have access to.

```bash
# Scan fleet and generate full HTML report
skywalker --all-projects --html compliance_report.html

# Scan fleet with high concurrency (faster for large orgs)
skywalker --all-projects --concurrency 20 --html fast_scan.html
```

#### 📄 Output Formats
Combine audit commands with output flags to generate artifacts.

```bash
# Generate a PDF report
skywalker --project-id ucr-research-computing --report audit.pdf

# Generate an HTML report
skywalker --project-id ucr-research-computing --html report.html

# Output raw JSON data (for piping to jq or saving)
skywalker --project-id ucr-research-computing --json > audit.json
```

#### ⚙️ Advanced Options

**Region Selection:**
Scan specific regions instead of the default US set.
```bash
skywalker --project-id ucr-research-computing --regions us-west1 us-east1
```

**Cache Control:**
Force a fresh scan by ignoring/clearing the local cache.
```bash
skywalker --project-id ucr-research-computing --no-cache
```

**Version Check:**
```bash
skywalker --version
```

## Options

| Flag | Description |
| :--- | :--- |
| `--project-id <ID>` | Target a single GCP project ID. |
| `--all-projects` | Discover and scan all active projects in the organization. |
| `--services <LIST>` | Specific services to audit: `compute`, `storage`, `gke`, `run`, `sql`, `iam`, `vertex`, `network`, or `all`. |
| `--regions <LIST>` | Regions to scan (default: `us-central1`, `us-west1`, `us-east1`, `us-east4`, `us-west2`, `us-west4`). |
| `--concurrency <N>` | Number of concurrent projects to scan (default: 5). |
| `--report <FILE>` | Generate a PDF report (requires `pango`/`cairo`). |
| `--html <FILE>` | Generate an HTML report. |
| `--json` | Output raw JSON to stdout (suppresses logs). |
| `--no-cache` | Disable and clear local cache for this run. |
| `--version` | Show the tool version. |

## Development

```bash
# Clone the repo
git clone https://github.com/charles-forsyth/Skywalker.git
cd Skywalker

# Install development environment
uv sync --extra dev --extra test

# Run tests
uv run pytest
```

---
*Maintained by Charles Forsyth / UCR Research Computing*