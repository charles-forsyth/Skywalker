# Skywalker 🚀

**GCP Audit & Reporting Tool for UCR Research Computing**

Skywalker is a high-performance CLI tool designed to "walk" the Google Cloud Platform (GCP) hierarchy to audit resources, validate security compliance (Ursa Major standards), and generate professional PDF reports.

## Features

- **Multi-Region Scanning:** Automatically audits the 6 major US regions concurrently.
- **Deep Inspection:** 
    - **Compute Engine:** VMs, Disks, GPUs, and IP addresses.
    - **Cloud Storage:** Bucket sizes (via Cloud Monitoring), Public Access Prevention (PAP) status, and versioning.
    - **Cloud Run:** Serverless service metadata and deployment history.
    - **GKE:** Kubernetes clusters and detailed node pool configurations.
- **Parallel Execution:** Uses Python's `ThreadPoolExecutor` for ultra-fast scanning.
- **Reporting:** Generates raw JSON data or professional PDF compliance reports.

## Getting Started

### 1. Installation

Skywalker is packaged for use with [uv](https://github.com/astral-sh/uv).

```bash
# Install Skywalker globally
uv tool install git+https://github.com/charles-forsyth/Skywalker.git
```

### 2. Authentication

Skywalker uses Google Cloud Application Default Credentials (ADC). You must authenticate your environment before running the tool.

**On your local machine:**
```bash
# Install gcloud CLI first, then:
gcloud auth login
gcloud auth application-default login
```

### 3. Usage

Run a full audit on a GCP project:

```bash
# Basic full audit (outputs to terminal)
skywalker --project-id your-gcp-project-id

# Generate a professional PDF report
skywalker --project-id your-gcp-project-id --pdf audit_report.pdf

# Export raw JSON data for processing
skywalker --project-id your-gcp-project-id --json > audit.json

# Audit specific services only
skywalker --project-id your-gcp-project-id --services storage compute
```

## Advanced Options

- `--regions`: List specific regions to scan (default: `us-central1`, `us-west1`, `us-east1`, `us-east4`, `us-west2`, `us-west4`).
- `--services`: Choose from `compute`, `storage`, `gke`, `run`, `sql`, `iam`, `vertex`, `network`, or `all`.

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