"""Google's own recommendations (Recommender API): idle resources, rightsizing,
commitments, unused IAM grants, with cost projections.

Recommenders are per location, so the zones and regions to ask come from the
project's Cloud Asset Inventory (where it actually has resources) plus global.
"""

from __future__ import annotations

from typing import Any

from .gcp import Gcp, GcpError
from .inventory import assets, locations_in_use
from .util import basename, clamp, money, parallel_map, project_id, r2

REC = "https://recommender.googleapis.com/v1"

ZONAL = [
    ("google.compute.instance.IdleResourceRecommender", "idle_vm"),
    ("google.compute.instance.MachineTypeRecommender", "rightsize_vm"),
    ("google.compute.disk.IdleResourceRecommender", "idle_disk"),
]
REGIONAL = [
    ("google.compute.address.IdleResourceRecommender", "idle_ip"),
    ("google.compute.commitment.UsageCommitmentRecommender", "commitment"),
    ("google.cloudsql.instance.IdleRecommender", "idle_sql"),
    ("google.cloudsql.instance.OverprovisionedRecommender", "overprovisioned_sql"),
]
GLOBAL = [
    ("google.compute.image.IdleResourceRecommender", "idle_image"),
    ("google.resourcemanager.projectUtilization.Recommender", "unattended_project"),
    ("google.iam.policy.Recommender", "iam_unused_role"),
]


def _cost(r: dict[str, Any]) -> float:
    """Monthly saving (positive) from the primary impact's cost projection."""
    imp = r.get("primaryImpact", {}) or {}
    cp = imp.get("costProjection", {}) or {}
    c = cp.get("cost", {}) or {}
    amount = money(c.get("units"), c.get("nanos"))
    dur = str(cp.get("duration", "2592000s")).rstrip("s")
    try:
        days = float(dur) / 86400 or 30
    except ValueError:
        days = 30
    return r2(-amount * 30 / days)


def _ask(gcp: Gcp, pid: str, loc: str, rid: str, label: str) -> list[dict[str, Any]]:
    url = f"{REC}/projects/{pid}/locations/{loc}/recommenders/{rid}/recommendations"
    try:
        rows = list(
            gcp.paged(
                url,
                {"filter": "stateInfo.state=ACTIVE"},
                "recommendations",
                limit=200,
                page_size=100,
            )
        )
    except GcpError as e:
        if e.kind in ("not_found", "invalid"):
            return []
        raise
    out = []
    for r in rows:
        ops_ = [
            op
            for g in (r.get("content", {}) or {}).get("operationGroups", []) or []
            for op in g.get("operations", []) or []
        ]
        res = [
            basename(op.get("resource"))
            for op in ops_
            if op.get("resource")
            and not str(op.get("resource")).startswith("$")
            and op.get("action") != "add"
        ] or [
            basename(op.get("resource"))
            for op in ops_
            if op.get("resource") and not str(op.get("resource")).startswith("$")
        ]
        member = next(
            (
                (op.get("pathFilters", {}) or {}).get(
                    "/iamPolicy/bindings/*/members/*", ""
                )
                for op in ops_
                if (op.get("pathFilters", {}) or {}).get(
                    "/iamPolicy/bindings/*/members/*"
                )
            ),
            "",
        )
        role = next(
            (
                (op.get("pathFilters", {}) or {}).get("/iamPolicy/bindings/*/role", "")
                for op in ops_
                if (op.get("pathFilters", {}) or {}).get("/iamPolicy/bindings/*/role")
            ),
            "",
        )
        out.append(
            {
                "kind": label,
                "location": loc,
                "description": r.get("description", ""),
                "resource": f"{member} {role}".strip()
                if member
                else (res[0] if res else ""),
                "monthly_saving": _cost(r),
                "priority": r.get("priority", ""),
                "category": (r.get("primaryImpact", {}) or {}).get("category", ""),
                "subtype": r.get("recommenderSubtype", ""),
            }
        )
    return out


def recommendations(
    gcp: Gcp, project: str, kinds: str = "", limit: int = 50
) -> dict[str, Any]:
    pid = project_id(project)
    zones, regions = locations_in_use(assets(gcp, pid))
    want = {k.strip() for k in kinds.split(",") if k.strip()} if kinds else set()
    asks: list[tuple[str, str, str]] = []
    for rid, label in ZONAL:
        asks += [(z, rid, label) for z in zones]
    for rid, label in REGIONAL:
        asks += [(r, rid, label) for r in regions]
    for rid, label in GLOBAL:
        asks.append(("global", rid, label))
    if want:
        asks = [a for a in asks if a[2] in want]
    res = parallel_map(lambda a: _ask(gcp, pid, *a), asks, workers=12)
    items: list[dict[str, Any]] = []
    errors: dict[str, Any] = {}
    for (loc, _rid, label), rows, e in res:
        if e:
            if e.get("error") == "api_disabled":
                return {
                    "project_id": pid,
                    "error": "api_disabled",
                    "message": "Recommender API is off for the quota project; ask an admin to enable it",
                }
            errors[f"{label}@{loc}"] = e
        else:
            items += rows or []
    items.sort(key=lambda r: -r["monthly_saving"])
    by_kind: dict[str, dict[str, float]] = {}
    for r in items:
        k = by_kind.setdefault(r["kind"], {"count": 0, "monthly_saving": 0.0})
        k["count"] += 1
        k["monthly_saving"] = r2(k["monthly_saving"] + r["monthly_saving"])
    n = clamp(limit, 1, 500)
    return {
        "project_id": pid,
        "asked": {"zones": zones, "regions": regions, "calls": len(asks)},
        "total_monthly_saving": r2(sum(r["monthly_saving"] for r in items)),
        "by_kind": by_kind,
        "items": items[:n],
        "truncated": len(items) > n,
        "errors": errors or None,
        "note": "savings are Google's projections at list price before credits",
    }
