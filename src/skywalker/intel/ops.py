"""Enabled APIs, recent admin activity (audit log), API traffic, and quotas."""

from __future__ import annotations

import datetime as dt
from typing import Any

from .gcp import Gcp, GcpError
from .util import basename, clamp, emailish, iso, now_utc, project_id, service_name

SU = "https://serviceusage.googleapis.com/v1"
LOG = "https://logging.googleapis.com/v2"
MON = "https://monitoring.googleapis.com/v3"
QUOTAS = "https://cloudquotas.googleapis.com/v1"

# APIs whose use usually costs real money or deserves a look.
COSTLY = {
    "aiplatform.googleapis.com",
    "generativelanguage.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "file.googleapis.com",
    "sqladmin.googleapis.com",
    "bigquery.googleapis.com",
    "notebooks.googleapis.com",
    "workstations.googleapis.com",
    "run.googleapis.com",
    "cloudfunctions.googleapis.com",
    "dataproc.googleapis.com",
    "batch.googleapis.com",
    "tpu.googleapis.com",
    "redis.googleapis.com",
    "alloydb.googleapis.com",
    "spanner.googleapis.com",
    "dataflow.googleapis.com",
    "translate.googleapis.com",
    "speech.googleapis.com",
    "texttospeech.googleapis.com",
    "vision.googleapis.com",
    "documentai.googleapis.com",
    "maps-backend.googleapis.com",
}


def enabled_services(gcp: Gcp, project: str) -> dict[str, Any]:
    pid = project_id(project)
    names = [
        s.get("config", {}).get("name", basename(s.get("name")))
        for s in gcp.paged(
            f"{SU}/projects/{pid}/services",
            {"filter": "state:ENABLED"},
            "services",
            limit=2000,
            page_size=200,
        )
    ]
    names.sort()
    return {
        "project_id": pid,
        "enabled": len(names),
        "costly_or_notable": [n for n in names if n in COSTLY],
        "services": names,
    }


def api_traffic(
    gcp: Gcp, project: str, days: int = 7, service: str = ""
) -> dict[str, Any]:
    """Requests per API (and per method for one API) from Cloud Monitoring."""
    pid = project_id(project)
    days = clamp(days, 1, 42)
    end = now_utc()
    start = end - dt.timedelta(days=days)
    filt = 'metric.type="serviceruntime.googleapis.com/api/request_count" AND resource.type="consumed_api"'
    group = ["resource.label.service", "metric.label.response_code_class"]
    if service:
        svc = service_name(service)
        filt += f' AND resource.label.service="{svc}"'
        group = ["resource.label.method", "metric.label.response_code_class"]
    params: list[tuple[str, Any]] = [
        ("filter", filt),
        ("interval.startTime", iso(start)),
        ("interval.endTime", iso(end)),
        ("aggregation.alignmentPeriod", f"{days * 86400}s"),
        ("aggregation.perSeriesAligner", "ALIGN_SUM"),
        ("aggregation.crossSeriesReducer", "REDUCE_SUM"),
        ("pageSize", "1000"),
    ] + [("aggregation.groupByFields", g) for g in group]
    data = gcp.get(f"{MON}/projects/{pid}/timeSeries", params)
    agg: dict[str, dict[str, int]] = {}
    for ts in data.get("timeSeries", []) or []:
        labels = {
            **(ts.get("resource", {}).get("labels", {}) or {}),
            **(ts.get("metric", {}).get("labels", {}) or {}),
        }
        key = labels.get("method") if service else labels.get("service")
        cls = labels.get("response_code_class", "")
        n = sum(
            int(p.get("value", {}).get("int64Value", 0) or 0)
            for p in ts.get("points", []) or []
        )
        a = agg.setdefault(key or "(none)", {"requests": 0, "errors": 0})
        a["requests"] += n
        if cls in ("4xx", "5xx"):
            a["errors"] += n
    rows: list[dict[str, Any]] = [{"name": k, **v} for k, v in agg.items()]
    rows.sort(key=lambda r: -r["requests"])
    return {
        "project_id": pid,
        "window_days": days,
        "by": "method" if service else "service",
        "service": service_name(service) if service else None,
        "total_requests": sum(r["requests"] for r in rows),
        "items": rows[:50],
        "hint": "aiplatform: GenerateContent = Gemini on Vertex, RawPredict/StreamRawPredict = "
        "Claude or other Model Garden models; generativelanguage = Gemini API keys",
    }


_WRITE_HINTS = (
    "insert",
    "create",
    "delete",
    "update",
    "patch",
    "set",
    "stop",
    "start",
    "enable",
    "disable",
    "resize",
    "attach",
    "detach",
    "add",
    "remove",
)


def activity(
    gcp: Gcp,
    project: str,
    days: int = 7,
    principal: str = "",
    method_contains: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Admin Activity audit log: who changed what (resource creates, deletes, IAM...)."""
    pid = project_id(project)
    days = clamp(days, 1, 30)
    since = iso(now_utc() - dt.timedelta(days=days))
    filt = (
        f'logName="projects/{pid}/logs/cloudaudit.googleapis.com%2Factivity" '
        f'AND timestamp>="{since}"'
    )
    if principal:
        filt += f' AND protoPayload.authenticationInfo.principalEmail:"{emailish(principal)}"'
    if method_contains:
        m = emailish(method_contains, "method")
        filt += f' AND protoPayload.methodName:"{m}"'
    entries: list[dict[str, Any]] = []
    tok = None
    n = clamp(limit, 1, 500)
    while len(entries) < n:
        body: dict[str, Any] = {
            "resourceNames": [f"projects/{pid}"],
            "filter": filt,
            "orderBy": "timestamp desc",
            "pageSize": min(500, n),
        }
        if tok:
            body["pageToken"] = tok
        data = gcp.post(f"{LOG}/entries:list", body, timeout=60)
        entries += data.get("entries", []) or []
        tok = data.get("nextPageToken")
        if not tok:
            break
    rows = []
    by_principal: dict[str, int] = {}
    by_method: dict[str, int] = {}
    for e in entries[:n]:
        p = e.get("protoPayload", {}) or {}
        who = (p.get("authenticationInfo", {}) or {}).get("principalEmail", "")
        meth = p.get("methodName", "")
        st = p.get("status", {}) or {}
        by_principal[who] = by_principal.get(who, 0) + 1
        short = meth.rsplit(".", 1)[-1] if meth else ""
        by_method[short] = by_method.get(short, 0) + 1
        rows.append(
            {
                "time": e.get("timestamp"),
                "who": who,
                "method": meth,
                "resource": p.get("resourceName", ""),
                "service": p.get("serviceName", ""),
                "error": st.get("message") if st.get("code") else None,
            }
        )
    return {
        "project_id": pid,
        "window_days": days,
        "entries": len(rows),
        "more": bool(tok),
        "by_principal": dict(sorted(by_principal.items(), key=lambda kv: -kv[1])),
        "by_method": dict(sorted(by_method.items(), key=lambda kv: -kv[1])[:25]),
        "items": rows,
    }


def quotas(
    gcp: Gcp, project: str, service: str = "compute.googleapis.com", limit: int = 40
) -> dict[str, Any]:
    """Quota limits for one service (GPUs, CPUs, IPs...) with non-default values flagged.

    Usage against regional Compute quotas comes from the Compute regions API.
    """
    pid = project_id(project)
    svc = service_name(service)
    rows = []
    try:
        for q in gcp.paged(
            f"{QUOTAS}/projects/{pid}/locations/global/services/{svc}/quotaInfos",
            {},
            "quotaInfos",
            limit=3000,
        ):
            dims = q.get("dimensionsInfos", []) or []
            name = (
                q.get("quotaDisplayName")
                or q.get("metricDisplayName")
                or q.get("quotaId")
            )
            for d in dims:
                val = (d.get("details", {}) or {}).get("value")
                if val in (None, "-1"):
                    continue
                rows.append(
                    {
                        "quota": name,
                        "id": q.get("quotaId"),
                        "where": (d.get("dimensions") or {}).get("region")
                        or (d.get("applicableLocations") or ["global"])[0],
                        "limit": int(str(val)),
                    }
                )
    except GcpError as e:
        if e.kind not in ("not_found", "invalid"):
            raise
    usage: list[dict[str, Any]] = []
    if svc == "compute.googleapis.com":
        reg = gcp.get(
            f"https://compute.googleapis.com/compute/v1/projects/{pid}/regions",
            {"maxResults": 100},
        )
        for r in reg.get("items", []) or []:
            for q in r.get("quotas", []) or []:
                lim, use = float(q.get("limit", 0)), float(q.get("usage", 0))
                if use > 0 and lim > 0:
                    usage.append(
                        {
                            "region": r.get("name"),
                            "metric": q.get("metric"),
                            "usage": use,
                            "limit": lim,
                            "pct": round(use / lim * 100, 1),
                        }
                    )
        usage.sort(key=lambda u: -u["pct"])
    gpu: dict[str, dict[str, Any]] = {}
    for r in rows:
        if "GPU" in str(r["quota"]).upper() and r["limit"] > 0:
            g = gpu.setdefault(
                str(r["quota"]), {"quota": r["quota"], "max_limit": 0, "regions": 0}
            )
            g["max_limit"] = max(g["max_limit"], r["limit"])
            g["regions"] += 1
    return {
        "project_id": pid,
        "service": svc,
        "in_use": usage[: clamp(limit, 1, 200)],
        "near_limit": [u for u in usage if u["pct"] >= 80],
        "gpu_quotas": sorted(gpu.values(), key=lambda g: str(g["quota"])),
        "quota_entries": len(rows),
    }
