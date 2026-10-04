"""Spend from the Cloud Billing BigQuery export, and budgets vs actual.

The export table and the job project are server config; callers pass only a
project id, a window and a grouping, which go in as query parameters. Every
query filters on the table's partition column (`_PARTITIONTIME`) and sets
`maximumBytesBilled`, so a query can't scan the whole 27 GB table by accident.

Gross = cost before credits; credits are negative; net = gross + credits.
Partitions are by export day, so the partition filter is widened by 3 days on
each side and the real window is applied to `usage_start_time`.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from .gcp import Gcp, GcpError
from .projects import number_map
from .util import IntelConfig, clamp, iso, money, period, project_id, r2

BUDGETS = "https://billingbudgets.googleapis.com/v1"

GROUPS = {
    "service": "service.description",
    "sku": "CONCAT(service.description, ' / ', sku.description)",
    "project": "project.id",
    "day": "CAST(DATE(usage_start_time, 'America/Los_Angeles') AS STRING)",
    "region": "IFNULL(location.region, 'global')",
    "label_lab": "(SELECT value FROM UNNEST(project.labels) WHERE key = 'lab' LIMIT 1)",
}

CREDITS = "IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)"


def _need(cfg: IntelConfig) -> None:
    if not cfg.billing_table or not cfg.job_project:
        raise GcpError("invalid", "billing export is not configured on this server")


def _params(start: dt.datetime, end: dt.datetime, **extra: str) -> list[dict[str, Any]]:
    p = [
        {
            "name": "start",
            "parameterType": {"type": "TIMESTAMP"},
            "parameterValue": {"value": iso(start)},
        },
        {
            "name": "end",
            "parameterType": {"type": "TIMESTAMP"},
            "parameterValue": {"value": iso(end)},
        },
        {
            "name": "pstart",
            "parameterType": {"type": "TIMESTAMP"},
            "parameterValue": {"value": iso(start - dt.timedelta(days=3))},
        },
        {
            "name": "pend",
            "parameterType": {"type": "TIMESTAMP"},
            "parameterValue": {"value": iso(end + dt.timedelta(days=3))},
        },
    ]
    for k, v in extra.items():
        p.append(
            {
                "name": k,
                "parameterType": {"type": "STRING"},
                "parameterValue": {"value": v},
            }
        )
    return p


WHERE = (
    "_PARTITIONTIME BETWEEN @pstart AND @pend "
    "AND usage_start_time >= @start AND usage_start_time < @end"
)


def spend(
    gcp: Gcp,
    cfg: IntelConfig,
    project: str = "",
    group_by: str = "service",
    days: int = 0,
    month: str = "",
    limit: int = 25,
) -> dict[str, Any]:
    """Gross, credits and net for one project (or every project, staff use)."""
    _need(cfg)
    if group_by not in GROUPS:
        raise GcpError("invalid", f"group_by must be one of {sorted(GROUPS)}")
    start, end, label = period(days or None, month or None)
    limit = clamp(limit, 1, 500)
    extra: dict[str, str] = {}
    where = WHERE
    if project:
        extra["project"] = project_id(project)
        where += " AND project.id = @project"
    key = GROUPS[group_by]
    sql = (
        f"SELECT {key} AS k, SUM(cost) AS gross, SUM({CREDITS}) AS credits, "
        f"SUM(cost) + SUM({CREDITS}) AS net "
        f"FROM `{cfg.billing_table}` WHERE {where} GROUP BY k ORDER BY gross DESC"
    )
    rows, meta = gcp.query(
        cfg.job_project, sql, _params(start, end, **extra), max_bytes=cfg.max_bytes
    )
    total_g = sum(r["gross"] or 0 for r in rows)
    total_c = sum(r["credits"] or 0 for r in rows)
    items = [
        {
            group_by: r["k"] or "(none)",
            "gross": r2(r["gross"]),
            "credits": r2(r["credits"]),
            "net": r2(r["net"]),
        }
        for r in rows
    ]
    if group_by == "day":
        items.sort(key=lambda x: x["day"])
    return {
        "project_id": extra.get("project", "(all visible to the export)"),
        "window": {"label": label, "start": iso(start), "end": iso(end)},
        "currency": "USD",
        "total": {
            "gross": r2(total_g),
            "credits": r2(total_c),
            "net": r2(total_g + total_c),
        },
        "group_by": group_by,
        "items": items[:limit] if group_by != "day" else items[-limit:],
        "truncated": len(items) > limit,
        "note": "gross = usage at our prices before credits; credits (PSSA/subscription) are negative",
        "query": {
            "bytes_processed": meta["bytes_processed"],
            "cache_hit": meta["cache_hit"],
        },
    }


def daily_by_project(
    gcp: Gcp, cfg: IntelConfig, start: dt.datetime, end: dt.datetime, project: str = ""
) -> list[dict[str, Any]]:
    _need(cfg)
    extra: dict[str, str] = {}
    where = WHERE
    if project:
        extra["project"] = project_id(project)
        where += " AND project.id = @project"
    sql = (
        "SELECT project.id AS project, project.number AS number, "
        "DATE(usage_start_time, 'America/Los_Angeles') AS day, SUM(cost) AS gross, "
        f"SUM({CREDITS}) AS credits FROM `{cfg.billing_table}` WHERE {where} "
        "GROUP BY project, number, day"
    )
    rows, _ = gcp.query(
        cfg.job_project, sql, _params(start, end, **extra), max_bytes=cfg.max_bytes
    )
    return rows


def trend(
    gcp: Gcp, cfg: IntelConfig, project: str = "", top_n: int = 15
) -> dict[str, Any]:
    """Last 7 days vs the 7 before, per project: who is speeding up."""
    _need(cfg)
    now = dt.datetime.now(dt.timezone.utc)
    rows = daily_by_project(gcp, cfg, now - dt.timedelta(days=14), now, project)
    cut = (now - dt.timedelta(days=7)).date()
    agg: dict[str, dict[str, float]] = {}
    account = {"last7": 0.0, "prev7": 0.0}
    for r in rows:
        day = dt.date.fromisoformat(str(r["day"]))
        slot = "last7" if day >= cut else "prev7"
        if not r["project"]:
            # Account-level charges (subscription fees, support) carry no project.
            account[slot] += float(r["gross"] or 0)
            continue
        a = agg.setdefault(r["project"], {"last7": 0.0, "prev7": 0.0})
        a[slot] += float(r["gross"] or 0)
    items: list[dict[str, Any]] = []
    for p, a in agg.items():
        delta = a["last7"] - a["prev7"]
        pct = (delta / a["prev7"] * 100) if a["prev7"] > 1 else None
        items.append(
            {
                "project_id": p,
                "gross_last7": r2(a["last7"]),
                "gross_prev7": r2(a["prev7"]),
                "change": r2(delta),
                "change_pct": round(pct, 1) if pct is not None else None,
                "per_day_now": r2(a["last7"] / 7),
            }
        )
    items.sort(key=lambda x: -x["change"])
    n = clamp(top_n, 1, 100)
    return {
        "window": "last 7 days vs previous 7 (gross, Pacific days; the newest day is partial)",
        "rising": items[:n],
        "falling": sorted(items, key=lambda x: x["change"])[:5],
        "projects": len(items),
        "account_level": {
            "gross_last7": r2(account["last7"]),
            "gross_prev7": r2(account["prev7"]),
            "note": "charges with no project (subscription, support); not in the lists above",
        },
    }


# --- Budgets ------------------------------------------------------------------


def _budget_row(b: dict[str, Any], numbers: dict[str, str]) -> dict[str, Any]:
    f = b.get("budgetFilter", {}) or {}
    amt = (b.get("amount", {}) or {}).get("specifiedAmount")
    nr = b.get("notificationsRule", {}) or {}
    projects = [numbers.get(p.split("/")[-1], p) for p in f.get("projects", []) or []]
    custom = f.get("customPeriod")
    return {
        "name": b.get("displayName", ""),
        "id": b.get("name", "").rsplit("/", 1)[-1],
        "projects": projects,
        "amount": money(amt.get("units"), amt.get("nanos")) if amt else None,
        "last_period_amount": bool((b.get("amount", {}) or {}).get("lastPeriodAmount")),
        "period": "custom" if custom else f.get("calendarPeriod", "MONTH"),
        "custom_start": custom.get("startDate") if custom else None,
        "custom_end": custom.get("endDate") if custom else None,
        "credits": f.get("creditTypesTreatment", ""),
        "services": f.get("services", []) or [],
        "thresholds": [
            t.get("thresholdPercent") for t in b.get("thresholdRules", []) or []
        ],
        "pubsub_topic": nr.get("pubsubTopic", ""),
        "channels": len(nr.get("monitoringNotificationChannels", []) or []),
        "default_iam_recipients": not nr.get("disableDefaultIamRecipients", False),
    }


def list_budgets(gcp: Gcp, cfg: IntelConfig) -> list[dict[str, Any]]:
    if not cfg.billing_account:
        raise GcpError("invalid", "billing account is not configured on this server")
    numbers = number_map(gcp)
    return [
        _budget_row(b, numbers)
        for b in gcp.paged(
            f"{BUDGETS}/billingAccounts/{cfg.billing_account}/budgets",
            {},
            "budgets",
            limit=5000,
        )
    ]


def budgets(
    gcp: Gcp, cfg: IntelConfig, project: str = "", status: str = "", limit: int = 50
) -> dict[str, Any]:
    """Every budget with this period's spend (gross, the way lab budgets count).

    status: over (>=100%), warn (>=75%), unbudgeted (spenders with no budget),
    or empty for all.
    """
    rows = list_budgets(gcp, cfg)
    pid = project_id(project) if project else ""
    if pid:
        rows = [b for b in rows if pid in b["projects"]]
    # This month's spend per project (calendar MONTH budgets; custom ones flagged).
    start, end, label = period()
    spend_rows = (
        daily_by_project(gcp, cfg, start, end, pid) if cfg.billing_table else []
    )
    mtd: dict[str, dict[str, float]] = {}
    for r in spend_rows:
        a = mtd.setdefault(
            r["project"] or "", {"gross": 0.0, "credits": 0.0, "d7": 0.0}
        )
        a["gross"] += float(r["gross"] or 0)
        a["credits"] += float(r["credits"] or 0)
        if dt.date.fromisoformat(str(r["day"])) >= (end - dt.timedelta(days=7)).date():
            a["d7"] += float(r["gross"] or 0)
    budgeted = set()
    for b in rows:
        g = sum(mtd.get(p, {}).get("gross", 0.0) for p in b["projects"])
        c = sum(mtd.get(p, {}).get("credits", 0.0) for p in b["projects"])
        d7 = sum(mtd.get(p, {}).get("d7", 0.0) for p in b["projects"])
        budgeted.update(b["projects"])
        incl = b["credits"] != "EXCLUDE_ALL_CREDITS"
        used = g + c if incl else g
        b["spend_this_month"] = r2(used)
        b["spend_basis"] = "net" if incl else "gross"
        b["per_day_7d"] = r2(d7 / 7)
        b["pct"] = round(used / b["amount"] * 100, 1) if b["amount"] else None
        b["period_note"] = (
            ""
            if b["period"] == "MONTH"
            else "not a calendar month; % uses this month's spend"
        )
        b["silenced_cap"] = bool(
            b["amount"] and b["amount"] >= 25000 and used < b["amount"] * 0.05
        )
    unbudgeted: list[dict[str, Any]] = [
        {
            "project_id": p,
            "gross_this_month": r2(a["gross"]),
            "per_day_7d": r2(a["d7"] / 7),
        }
        for p, a in mtd.items()
        if p and p not in budgeted and a["gross"] >= 1
    ]
    unbudgeted.sort(key=lambda x: -x["gross_this_month"])
    over = [b for b in rows if b["pct"] is not None and b["pct"] >= 100]
    warn = [b for b in rows if b["pct"] is not None and 75 <= b["pct"] < 100]
    dup: dict[str, int] = {}
    for b in rows:
        for p in b["projects"]:
            dup[p] = dup.get(p, 0) + 1
    if status == "over":
        shown = over
    elif status == "warn":
        shown = warn
    elif status == "unbudgeted":
        shown = []
    elif status:
        raise GcpError("invalid", "status must be over, warn, unbudgeted or empty")
    else:
        shown = rows
    shown = sorted(shown, key=lambda b: -(b["pct"] or 0))
    n = clamp(limit, 1, 1000)
    return {
        "billing_account": cfg.billing_account,
        "month": label,
        "summary": {
            "budgets": len(rows),
            "over_100pct": len(over),
            "75_to_100pct": len(warn),
            "silenced_high_caps": sum(1 for b in rows if b["silenced_cap"]),
            "projects_with_two_or_more_budgets": sorted(
                p for p, n_ in dup.items() if n_ > 1
            ),
            "without_pubsub_throttle": sum(1 for b in rows if not b["pubsub_topic"]),
            "unbudgeted_spenders": len(unbudgeted),
        },
        "budgets": shown[:n],
        "unbudgeted": unbudgeted[:n] if status in ("", "unbudgeted") else [],
        "truncated": len(shown) > n,
        "note": "spend computed from the billing export (Pacific month), not Google's own budget figure; "
        "spend caps (Preview) are not returned by the Budgets API",
    }
