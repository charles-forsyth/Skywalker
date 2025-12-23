# Skywalker

**Skywalker** is the official GCP Audit & Reporting Tool for **UCR Research Computing**. It provides deep visibility into the "Ursa Major" research fleet, helping administrators detect security risks, optimize costs, and maintain operational hygiene across hundreds of Google Cloud projects.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Production-orange)

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
*   **Calculates ROI:** Estimates potential monthly savings (e.g., "$19,000/mo potential savings").

### 4. 🛠️ Automated Remediation
Interactive "Fix-It" mode to solve common fleet issues at scale.
*   **Ops Agent Installer:** Mass-deploys the Google Cloud Ops Agent to Linux VMs via SSH (IAP Tunneling) to fix monitoring blind spots.

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
2.  Write tests (`pytest`).
3.  Ensure typing passes (`mypy src`).
4.  Format code (`ruff format .`).
5.  Submit a PR.

---
*Maintained by Charles Forsyth (UCR Research Computing)*
