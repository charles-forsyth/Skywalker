# Skywalker 🚀

**GCP Audit & Reporting Tool for UCR Research Computing**

Skywalker is a high-performance CLI tool designed to "walk" the Google Cloud Platform (GCP) hierarchy to audit resources, validate security compliance (Ursa Major standards), and generate professional reports.

## Features

- **Fleet Commander:** Automatically discovers and audits ALL active projects in your organization/folder.
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

## Getting Started

### 1. Installation

Skywalker is packaged for use with [uv](https://github.com/astral-sh/uv).

```bash
# Install Skywalker globally
uv tool install git+https://github.com/charles-forsyth/Skywalker.git
```

### 2. Authentication

Skywalker uses Google Cloud Application Default Credentials (ADC).

```bash
gcloud auth login
gcloud auth application-default login
```

### 3. Usage

#### Single Project Audit
```bash
# Basic scan (outputs to terminal)
skywalker --project-id ucr-research-computing

# Generate a PDF report
skywalker --project-id ucr-research-computing --report audit.pdf

# Audit specific services only
skywalker --project-id ucr-research-computing --services iam network sql
```

#### Fleet Audit (Multi-Project)
Scan all projects you have access to:

```bash
# Scan fleet and generate full HTML report
skywalker --all-projects --html fleet_report.html

# Export raw data for the entire fleet to JSON
skywalker --all-projects --json > fleet_data.json
```

## Options

- `--project-id`: Target a single project.
- `--all-projects`: Discover and scan all active projects.
- `--regions`: List specific regions to scan (default: Major US regions).
- `--services`: Choose from `compute`, `storage`, `gke`, `run`, `sql`, `iam`, `vertex`, `network`, or `all`.
- `--json`: Output JSON to stdout (suppresses logs).
- `--report` / `--pdf`: Output PDF report.
- `--html`: Output HTML report.
- `--concurrency`: Number of concurrent projects to scan (default: 5).

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
