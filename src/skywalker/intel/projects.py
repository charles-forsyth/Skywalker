"""Projects the caller can see, and one project's identity and billing link."""

from __future__ import annotations

from typing import Any

from .gcp import Gcp, GcpError
from .util import basename, clamp, project_id, project_query

RM = "https://cloudresourcemanager.googleapis.com/v3"
BILLING = "https://cloudbilling.googleapis.com/v1"


def all_projects(gcp: Gcp, limit: int = 3000) -> list[dict[str, Any]]:
    """Every ACTIVE project visible to the caller (Resource Manager search)."""
    out = []
    for p in gcp.paged(
        f"{RM}/projects:search", {"query": "state:ACTIVE"}, "projects", limit=limit
    ):
        out.append(
            {
                "project_id": p.get("projectId", ""),
                "number": basename(p.get("name")),
                "name": p.get("displayName", ""),
                "parent": p.get("parent", ""),
                "created": p.get("createTime", ""),
                "labels": p.get("labels", {}) or {},
            }
        )
    return out


def number_map(gcp: Gcp) -> dict[str, str]:
    """project number -> project id for every visible project."""
    return {p["number"]: p["project_id"] for p in all_projects(gcp)}


def list_projects(gcp: Gcp, query: str = "", limit: int = 100) -> dict[str, Any]:
    limit = clamp(limit, 1, 1000)
    q = project_query(query).lower() if query else ""
    rows = all_projects(gcp)
    if q:
        rows = [
            p
            for p in rows
            if q in p["project_id"].lower()
            or q in p["name"].lower()
            or any(q in f"{k}={v}".lower() for k, v in p["labels"].items())
        ]
    rows.sort(key=lambda p: p["project_id"])
    by_parent: dict[str, int] = {}
    for p in rows:
        by_parent[p["parent"]] = by_parent.get(p["parent"], 0) + 1
    return {
        "total": len(rows),
        "by_parent": by_parent,
        "projects": rows[:limit],
        "truncated": len(rows) > limit,
    }


def project_info(gcp: Gcp, project: str) -> dict[str, Any]:
    pid = project_id(project)
    p = gcp.get(f"{RM}/projects/{pid}")
    info: dict[str, Any] = {
        "project_id": p.get("projectId", pid),
        "number": basename(p.get("name")),
        "name": p.get("displayName", ""),
        "state": p.get("state", ""),
        "parent": p.get("parent", ""),
        "created": p.get("createTime", ""),
        "labels": p.get("labels", {}) or {},
    }
    try:
        b = gcp.get(f"{BILLING}/projects/{pid}/billingInfo")
        info["billing_enabled"] = bool(b.get("billingEnabled"))
        info["billing_account"] = basename(b.get("billingAccountName"))
    except GcpError as e:
        info["billing_enabled"] = None
        info["billing_error"] = e.kind
    return info
