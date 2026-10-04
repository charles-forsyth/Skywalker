"""Who has access, service accounts and their keys, API keys and their use."""

from __future__ import annotations

import datetime as dt
import functools
from collections.abc import Callable
from typing import Any

from .gcp import Gcp, GcpError
from .util import (
    IntelConfig,
    age_days,
    basename,
    clamp,
    iso,
    now_utc,
    project_id,
    sections,
)

RM1 = "https://cloudresourcemanager.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
APIKEYS = "https://apikeys.googleapis.com/v2"
PA = "https://policyanalyzer.googleapis.com/v1"
MON = "https://monitoring.googleapis.com/v3"
REC = "https://recommender.googleapis.com/v1"

PRIVILEGED = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/compute.admin",
    "roles/storage.admin",
}


def _kind(member: str) -> str:
    return member.split(":", 1)[0] if ":" in member else member


def policy(gcp: Gcp, project: str) -> dict[str, Any]:
    pid = project_id(project)
    return gcp.post(
        f"{RM1}/projects/{pid}:getIamPolicy", {"options": {"requestedPolicyVersion": 3}}
    )


def access(
    gcp: Gcp, cfg: IntelConfig, project: str, principal: str = ""
) -> dict[str, Any]:
    """Project IAM: who holds which role, flagged for risk."""
    pid = project_id(project)
    pol = policy(gcp, pid)
    members: dict[str, dict[str, Any]] = {}
    for b in pol.get("bindings", []) or []:
        role = b.get("role", "")
        cond = (b.get("condition") or {}).get("title", "")
        for m in b.get("members", []) or []:
            e = members.setdefault(m, {"member": m, "type": _kind(m), "roles": []})
            e["roles"].append(role + (f" (if: {cond})" if cond else ""))
    rows = list(members.values())
    dom = "@" + cfg.domain
    for r in rows:
        m = r["member"]
        flags = []
        bare = {x.split(" (if")[0] for x in r["roles"]}
        if m in ("allUsers", "allAuthenticatedUsers"):
            flags.append("public")
        if r["type"] == "user" and not m.endswith(dom):
            flags.append("outside_domain")
        if r["type"] == "deleted" or m.startswith("deleted:"):
            flags.append("deleted_principal")
        if bare & PRIVILEGED:
            flags.append("privileged")
        if (
            r["type"] == "serviceAccount"
            and m.endswith("-compute@developer.gserviceaccount.com")
            and (bare & {"roles/owner", "roles/editor"})
        ):
            flags.append(
                "default_compute_sa_is_"
                + ("owner" if "roles/owner" in bare else "editor")
            )
        r["flags"] = flags
    if principal:
        q = principal.lower()
        rows = [r for r in rows if q in r["member"].lower()]
    by_role: dict[str, int] = {}
    for r in rows:
        for role in r["roles"]:
            by_role[role] = by_role.get(role, 0) + 1
    rows.sort(key=lambda r: (-len(r["flags"]), r["member"]))
    return {
        "project_id": pid,
        "members": len(rows),
        "owners": sorted(
            r["member"]
            for r in rows
            if any(x.startswith("roles/owner") for x in r["roles"])
        ),
        "flagged": [r for r in rows if r["flags"]],
        "by_role": dict(sorted(by_role.items(), key=lambda kv: -kv[1])),
        "all": rows[:200],
        "truncated": len(rows) > 200,
    }


def _sa_last_auth(gcp: Gcp, pid: str) -> dict[str, str]:
    """service account email (and key id) -> last authenticated time."""
    out: dict[str, str] = {}
    for kind in (
        "serviceAccountLastAuthentication",
        "serviceAccountKeyLastAuthentication",
    ):
        try:
            for a in gcp.paged(
                f"{PA}/projects/{pid}/locations/global/activityTypes/{kind}/activities:query",
                {},
                "activities",
                limit=2000,
                page_size=1000,
            ):
                name = a.get("fullResourceName", "")
                ts = (a.get("activity", {}) or {}).get("lastAuthenticatedTime", "")
                key = (
                    basename(name)
                    if "/keys/" in name
                    else name.split("/serviceAccounts/")[-1]
                )
                if ts:
                    out[key] = ts
        except GcpError:
            continue
    return out


def service_accounts(gcp: Gcp, project: str, key_age_days: int = 90) -> dict[str, Any]:
    """Service accounts, their user-managed keys (age), and last use."""
    pid = project_id(project)
    accts = list(
        gcp.paged(
            f"{IAM}/projects/{pid}/serviceAccounts",
            {},
            "accounts",
            limit=2000,
            page_size=100,
        )
    )
    last = _sa_last_auth(gcp, pid)

    def keys_for(email: str) -> list[dict[str, Any]]:
        data = gcp.get(
            f"{IAM}/projects/{pid}/serviceAccounts/{email}/keys",
            {"keyTypes": "USER_MANAGED"},
        )
        out = []
        for k in data.get("keys", []) or []:
            kid = basename(k.get("name"))
            out.append(
                {
                    "key_id": kid[:12] + "...",
                    "created": k.get("validAfterTime"),
                    "age_days": age_days(k.get("validAfterTime")),
                    "expires": k.get("validBeforeTime"),
                    "disabled": bool(k.get("disabled")),
                    "last_used": last.get(kid),
                }
            )
        return out

    jobs: dict[str, Callable[[], Any]] = {
        a["email"]: functools.partial(keys_for, a["email"]) for a in accts
    }
    keys, errors = sections(jobs, workers=8) if jobs else ({}, {})
    rows = []
    for a in accts:
        email = a.get("email", "")
        ks = keys.get(email, [])
        lu = last.get(email)
        rows.append(
            {
                "email": email,
                "name": a.get("displayName", ""),
                "disabled": bool(a.get("disabled")),
                "user_managed_keys": ks,
                "old_keys": sum(
                    1
                    for k in ks
                    if (k["age_days"] or 0) > key_age_days and not k["disabled"]
                ),
                "last_authenticated": lu,
                "idle_days": age_days(lu) if lu else None,
            }
        )
    rows.sort(key=lambda r: (-r["old_keys"], -len(r["user_managed_keys"]), r["email"]))
    return {
        "project_id": pid,
        "service_accounts": len(rows),
        "with_user_keys": sum(1 for r in rows if r["user_managed_keys"]),
        "keys_older_than_days": key_age_days,
        "old_keys": sum(r["old_keys"] for r in rows),
        "never_or_long_unused": [
            r["email"]
            for r in rows
            if r["last_authenticated"] is None or (r["idle_days"] or 0) > 90
        ],
        "accounts": rows,
        "errors": errors or None,
        "note": "last use comes from Policy Analyzer (about 2 days behind); "
        "none means no authentication seen in its window",
    }


def _key_usage(gcp: Gcp, pid: str, days: int) -> dict[str, dict[str, int]]:
    """credential uid -> {service: requests} over `days` (Monitoring)."""
    end = now_utc()
    start = end - dt.timedelta(days=days)
    params = [
        (
            "filter",
            'metric.type="serviceruntime.googleapis.com/api/request_count" '
            'AND resource.type="consumed_api"',
        ),
        ("interval.startTime", iso(start)),
        ("interval.endTime", iso(end)),
        ("aggregation.alignmentPeriod", f"{days * 86400}s"),
        ("aggregation.perSeriesAligner", "ALIGN_SUM"),
        ("aggregation.crossSeriesReducer", "REDUCE_SUM"),
        ("aggregation.groupByFields", "metric.label.credential_id"),
        ("aggregation.groupByFields", "resource.label.service"),
        ("pageSize", "1000"),
    ]
    out: dict[str, dict[str, int]] = {}
    data = gcp.get(f"{MON}/projects/{pid}/timeSeries", params)
    for ts in data.get("timeSeries", []) or []:
        cred = (ts.get("metric", {}).get("labels", {}) or {}).get("credential_id", "")
        svc = (ts.get("resource", {}).get("labels", {}) or {}).get("service", "")
        n = sum(
            int(p.get("value", {}).get("int64Value", 0) or 0)
            for p in ts.get("points", []) or []
        )
        if cred.startswith("apikey:"):
            out.setdefault(cred.split(":", 1)[1], {})[svc] = (
                out.get(cred.split(":", 1)[1], {}).get(svc, 0) + n
            )
    return out


def api_keys(gcp: Gcp, project: str, days: int = 30) -> dict[str, Any]:
    """API keys, their restrictions, and requests per key (key strings never fetched)."""
    pid = project_id(project)
    days = clamp(days, 1, 42)
    keys = list(
        gcp.paged(
            f"{APIKEYS}/projects/{pid}/locations/global/keys",
            {},
            "keys",
            limit=500,
            page_size=300,
        )
    )
    try:
        usage = _key_usage(gcp, pid, days)
        usage_err = None
    except GcpError as e:
        usage, usage_err = {}, e.as_dict()
    rows = []
    for k in keys:
        r = k.get("restrictions", {}) or {}
        targets = [t.get("service", "") for t in r.get("apiTargets", []) or []]
        app = [
            n
            for n in (
                "browserKeyRestrictions",
                "serverKeyRestrictions",
                "androidKeyRestrictions",
                "iosKeyRestrictions",
            )
            if n in r
        ]
        uid = k.get("uid", "")
        used = usage.get(uid, {})
        flags = []
        if not targets:
            flags.append("no_api_restriction")
        if not app:
            flags.append("no_application_restriction")
        if k.get("serviceAccountEmail"):
            flags.append("bound_to_service_account")
        rows.append(
            {
                "name": k.get("displayName") or basename(k.get("name")),
                "created": k.get("createTime"),
                "age_days": age_days(k.get("createTime")),
                "api_targets": targets,
                "application_restrictions": app,
                "service_account": k.get("serviceAccountEmail", ""),
                f"requests_{days}d": sum(used.values()),
                "requests_by_service": used,
                "flags": flags,
            }
        )
    rows.sort(key=lambda r: -r[f"requests_{days}d"])
    return {
        "project_id": pid,
        "keys": len(rows),
        "unrestricted": sum(1 for r in rows if "no_api_restriction" in r["flags"]),
        "unused_in_window": [r["name"] for r in rows if not r[f"requests_{days}d"]],
        "window_days": days,
        "items": rows,
        "usage_error": usage_err,
        "note": "requests, not dollars; key strings are never read",
    }


def iam_recommendations(gcp: Gcp, project: str, limit: int = 25) -> dict[str, Any]:
    """IAM recommender: roles granted but unused in the last 90 days."""
    pid = project_id(project)
    rows = []
    for r in gcp.paged(
        f"{REC}/projects/{pid}/locations/global/recommenders/google.iam.policy.Recommender/recommendations",
        {"filter": "stateInfo.state=ACTIVE"},
        "recommendations",
        limit=clamp(limit, 1, 200),
        page_size=100,
    ):
        ops = [
            op
            for g in (r.get("content", {}) or {}).get("operationGroups", []) or []
            for op in g.get("operations", []) or []
        ]
        rows.append(
            {
                "description": r.get("description", ""),
                "subtype": r.get("recommenderSubtype", ""),
                "priority": r.get("priority", ""),
                "member": next(
                    (
                        (op.get("pathFilters", {}) or {}).get(
                            "/iamPolicy/bindings/*/members/*", ""
                        )
                        for op in ops
                        if op.get("pathFilters")
                    ),
                    "",
                ),
                "changes": [
                    f"{op.get('action')} {(op.get('pathFilters', {}) or {}).get('/iamPolicy/bindings/*/role', '')}"
                    f"{(op.get('value') or '') and ' ' + str(op.get('value'))}"
                    for op in ops
                ][:4],
            }
        )
    return {"project_id": pid, "recommendations": rows, "count": len(rows)}
