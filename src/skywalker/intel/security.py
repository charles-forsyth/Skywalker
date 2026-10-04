"""Security posture: public exposure, open admin ports, and SCC findings."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .gcp import Gcp
from .util import basename, clamp, project_id, sections

ASSET = "https://cloudasset.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
SCC = "https://securitycenter.googleapis.com/v2"

ADMIN_PORTS = {
    "22": "ssh",
    "3389": "rdp",
    "5432": "postgres",
    "3306": "mysql",
    "6379": "redis",
    "27017": "mongodb",
    "9200": "elasticsearch",
    "8888": "jupyter",
    "2375": "docker",
}
OPEN = ("0.0.0.0/0", "::/0")


def _port_hits(allowed: list[dict[str, Any]]) -> list[str]:
    hits = []
    for a in allowed:
        proto = a.get("IPProtocol", "")
        ports = a.get("ports") or (
            ["0-65535"] if proto in ("all", "tcp", "udp") else []
        )
        for p in ports:
            lo, _, hi = str(p).partition("-")
            lo_i, hi_i = int(lo), int(hi or lo)
            for port, name in ADMIN_PORTS.items():
                if lo_i <= int(port) <= hi_i:
                    hits.append(
                        f"{name}:{port}"
                        if (hi_i - lo_i) < 1000
                        else f"all ports ({proto})"
                    )
    return sorted(set(hits))


def open_firewalls(gcp: Gcp, pid: str) -> list[dict[str, Any]]:
    out = []
    for f in gcp.paged(
        f"{COMPUTE}/projects/{pid}/global/firewalls",
        {},
        "items",
        limit=2000,
        page_size_param="maxResults",
    ):
        if f.get("disabled") or f.get("direction", "INGRESS") != "INGRESS":
            continue
        src = f.get("sourceRanges", []) or []
        if not any(s in OPEN for s in src):
            continue
        hits = _port_hits(f.get("allowed", []) or [])
        if hits:
            out.append(
                {
                    "rule": f.get("name"),
                    "network": basename(f.get("network")),
                    "exposes": hits,
                    "target_tags": f.get("targetTags", []) or [],
                    "priority": f.get("priority"),
                }
            )
    return out


def public_bindings(gcp: Gcp, pid: str) -> list[dict[str, Any]]:
    out = []
    for r in gcp.paged(
        f"{ASSET}/projects/{pid}:searchAllIamPolicies",
        {"query": "memberTypes:(allUsers OR allAuthenticatedUsers)"},
        "results",
        limit=500,
    ):
        roles = sorted(
            {
                b.get("role", "")
                for b in (r.get("policy", {}) or {}).get("bindings", []) or []
                if any(
                    m in ("allUsers", "allAuthenticatedUsers")
                    for m in b.get("members", []) or []
                )
            }
        )
        out.append(
            {
                "resource": r.get("resource", "").replace("//", ""),
                "type": r.get("assetType", ""),
                "public_roles": roles,
            }
        )
    return out


def external_vms(gcp: Gcp, pid: str) -> list[dict[str, Any]]:
    out = []
    for r in gcp.paged(
        f"{ASSET}/projects/{pid}:searchAllResources",
        {
            "assetTypes": "compute.googleapis.com/Instance",
            "readMask": "name,location,state,additionalAttributes",
        },
        "results",
        limit=2000,
    ):
        ips = (r.get("additionalAttributes", {}) or {}).get("externalIPs", []) or []
        if ips:
            out.append(
                {
                    "vm": basename(r.get("name")),
                    "zone": r.get("location"),
                    "state": r.get("state"),
                    "external_ips": ips,
                }
            )
    return out


def scc_findings(gcp: Gcp, pid: str, limit: int = 50) -> dict[str, Any]:
    by_sev: dict[str, int] = {}
    rows = []
    for f in gcp.paged(
        f"{SCC}/projects/{pid}/sources/-/locations/global/findings",
        {"filter": 'state="ACTIVE" AND mute!="MUTED"'},
        "listFindingsResults",
        limit=1000,
    ):
        fd = f.get("finding", {}) or {}
        sev = fd.get("severity", "SEVERITY_UNSPECIFIED")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        rows.append(
            {
                "category": fd.get("category"),
                "severity": sev,
                "class": fd.get("findingClass"),
                "resource": basename(fd.get("resourceName")),
                "since": fd.get("eventTime"),
            }
        )
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: order.get(r["severity"], 9))
    return {
        "active": len(rows),
        "by_severity": by_sev,
        "top": rows[: clamp(limit, 1, 200)],
    }


def exposure(gcp: Gcp, project: str, include_scc: bool = True) -> dict[str, Any]:
    pid = project_id(project)
    jobs: dict[str, Callable[[], Any]] = {
        "public_iam": lambda: public_bindings(gcp, pid),
        "open_firewall_rules": lambda: open_firewalls(gcp, pid),
        "vms_with_external_ip": lambda: external_vms(gcp, pid),
    }
    if include_scc:
        jobs["security_command_center"] = lambda: scc_findings(gcp, pid)
    got, errors = sections(jobs)
    risk = []
    for b in got.get("public_iam", []):
        if b["type"] == "run.googleapis.com/Service" and b["public_roles"] == [
            "roles/run.invoker"
        ]:
            risk.append(
                f"Cloud Run service {basename(b['resource'])} accepts unauthenticated requests "
                "(fine if the app does its own sign-in; check it does)"
            )
        else:
            risk.append(
                f"public access ({', '.join(b['public_roles'])}) on {b['resource']}"
            )
    for f in got.get("open_firewall_rules", []):
        risk.append(
            f"firewall {f['rule']} opens {', '.join(f['exposes'])} to the internet"
        )
    scc = got.get("security_command_center") or {}
    for sev in ("CRITICAL", "HIGH"):
        if scc.get("by_severity", {}).get(sev):
            risk.append(
                f"{scc['by_severity'][sev]} {sev.lower()} Security Command Center findings"
            )
    out = {"project_id": pid, "risks": risk, **got}
    if errors:
        out["errors"] = errors
    return out
