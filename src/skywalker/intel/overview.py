"""The one-call answers: a project briefing, and a fleet overview.

`overview(project)` runs the cheap, high-signal checks in parallel and turns
them into a short list of findings ("what is happening here"), with the detail
sections attached. Each section that fails (API off, no permission) becomes a
note, never a failed briefing.
"""

from __future__ import annotations

from typing import Any

from . import billing, iam, inventory, ops, projects, recommend, security
from .gcp import Gcp, GcpError
from .util import IntelConfig, clamp, iso, now_utc, project_id, sections

ASSET = "https://cloudasset.googleapis.com/v1"


def _sa_role(flags: set[str]) -> str:
    hit = next(x for x in flags if x.startswith("default_compute_sa_is_"))
    return hit.rsplit("_", 1)[-1]


def _findings(s: dict[str, Any]) -> list[dict[str, str]]:
    f: list[dict[str, str]] = []

    def add(level: str, area: str, text: str) -> None:
        f.append({"level": level, "area": area, "text": text})

    info = s.get("project") or {}
    if info and info.get("billing_enabled") is False:
        add("info", "billing", "billing is disabled on this project")
    sp = s.get("spend") or {}
    tr = s.get("trend") or {}
    bud = s.get("budget") or {}
    if sp:
        tot = sp.get("total", {})
        top = (sp.get("items") or [{}])[0]
        if tot.get("gross", 0) >= 1:
            add(
                "info",
                "spend",
                f"{sp['window']['label']}: ${tot['gross']:,.2f} gross, ${tot['net']:,.2f} net"
                + (
                    f"; biggest: {top.get('service')} ${top.get('gross', 0):,.2f}"
                    if top
                    else ""
                ),
            )
    rising = (tr.get("rising") or [{}])[0] if tr else {}
    if (
        rising
        and rising.get("change", 0) > 50
        and (rising.get("change_pct") or 999) > 50
    ):
        add(
            "warn",
            "spend",
            f"spend is rising: ${rising['gross_last7']:,.2f} last 7 days vs "
            f"${rising['gross_prev7']:,.2f} the week before (${rising['per_day_now']:,.2f}/day now)",
        )
    for b in bud.get("budgets", []) or []:
        if b.get("pct") is not None and b["pct"] >= 100:
            add(
                "alert",
                "budget",
                f"budget '{b['name']}' is at {b['pct']}% (${b['spend_this_month']:,.2f} of ${b['amount']:,.0f})",
            )
        elif b.get("pct") is not None and b["pct"] >= 75:
            add("warn", "budget", f"budget '{b['name']}' is at {b['pct']}%")
        if b.get("silenced_cap"):
            add(
                "info",
                "budget",
                f"budget '{b['name']}' cap ${b['amount']:,.0f} is far above use (alerts effectively off)",
            )
        if not b.get("pubsub_topic"):
            add(
                "info",
                "budget",
                f"budget '{b['name']}' has no Pub/Sub topic (no automatic throttle)",
            )
    if (
        bud
        and not bud.get("budgets")
        and sp
        and sp.get("total", {}).get("gross", 0) >= 1
    ):
        add("warn", "budget", "this project spends money but has no budget")
    c = (s.get("compute") or {}).get("summary") or {}
    if c:
        if c.get("vms_running"):
            gp = c.get("gpus_running") or []
            add(
                "info",
                "compute",
                f"{c['vms_running']} of {c['vms']} VMs running"
                + (f"; GPUs: {', '.join(gp)}" if gp else ""),
            )
        if c.get("unattached_disk_gb", 0) >= 100:
            add(
                "warn",
                "waste",
                f"{c['unattached_disks']} unattached disks, {c['unattached_disk_gb']:,} GB still billing",
            )
        if c.get("unused_external_ips"):
            add(
                "warn",
                "waste",
                f"{c['unused_external_ips']} reserved external IPs not in use",
            )
        if c.get("snapshot_stored_gb", 0) >= 500:
            add(
                "info",
                "waste",
                f"{c['snapshots']} snapshots storing {c['snapshot_stored_gb']:,} GB",
            )
    rec = s.get("recommendations") or {}
    if rec.get("total_monthly_saving", 0) >= 10:
        kinds = ", ".join(
            f"{k} x{v['count']}"
            for k, v in (rec.get("by_kind") or {}).items()
            if v.get("monthly_saving", 0) > 0
        )
        add(
            "warn",
            "waste",
            f"Google recommends changes worth about ${rec['total_monthly_saving']:,.0f}/month ({kinds})",
        )
    ex = s.get("exposure") or {}
    for r in ex.get("risks", []) or []:
        level = (
            "warn"
            if r.startswith("Cloud Run service")
            else ("alert" if "firewall" in r or "public" in r else "warn")
        )
        add(level, "security", r)
    acc = s.get("access") or {}
    for m in acc.get("flagged", []) or []:
        fl = set(m.get("flags", []))
        if "public" in fl:
            add(
                "alert",
                "iam",
                f"{m['member']} holds {', '.join(m['roles'])} on the project",
            )
        if "outside_domain" in fl:
            add(
                "warn",
                "iam",
                f"outside account {m['member']} has {', '.join(r.split(' (if')[0] for r in m['roles'])}",
            )
        if any(x.startswith("default_compute_sa_is_") for x in fl):
            add(
                "warn",
                "iam",
                f"default compute service account is {_sa_role(fl)}",
            )
        if "deleted_principal" in fl:
            add("info", "iam", f"stale binding for deleted principal {m['member']}")
    sa = s.get("service_accounts") or {}
    if sa.get("old_keys"):
        add(
            "warn",
            "iam",
            f"{sa['old_keys']} user-managed service account keys older than {sa['keys_older_than_days']} days",
        )
    keys = s.get("api_keys") or {}
    if keys.get("unrestricted"):
        add(
            "warn",
            "api_keys",
            f"{keys['unrestricted']} of {keys['keys']} API keys have no API restriction",
        )
    act = s.get("activity") or {}
    if act.get("entries"):
        who = ", ".join(list((act.get("by_principal") or {}).keys())[:3])
        add(
            "info",
            "activity",
            f"{act['entries']}{'+' if act.get('more') else ''} admin changes in {act['window_days']} days (most by {who})",
        )
    order = {"alert": 0, "warn": 1, "info": 2}
    f.sort(key=lambda x: order.get(x["level"], 9))
    return f


def overview(
    gcp: Gcp, cfg: IntelConfig, project: str, deep: bool = False
) -> dict[str, Any]:
    """Everything worth knowing about one project right now."""
    pid = project_id(project)
    jobs: dict[str, Any] = {
        "project": lambda: projects.project_info(gcp, pid),
        "assets": lambda: inventory.summarize_assets(inventory.assets(gcp, pid)),
        "compute": lambda: inventory.compute(gcp, pid, limit=15),
        "services": lambda: ops.enabled_services(gcp, pid),
        "access": lambda: iam.access(gcp, cfg, pid),
        "exposure": lambda: security.exposure(gcp, pid, include_scc=True),
        "activity": lambda: ops.activity(gcp, pid, days=7, limit=100),
        "api_keys": lambda: iam.api_keys(gcp, pid, days=30),
        "traffic": lambda: ops.api_traffic(gcp, pid, days=7),
    }
    if cfg.billing_table:
        jobs["spend"] = lambda: billing.spend(gcp, cfg, pid, "service", limit=8)
        jobs["trend"] = lambda: billing.trend(gcp, cfg, pid, top_n=1)
    if cfg.billing_account:
        jobs["budget"] = lambda: billing.budgets(gcp, cfg, pid)
    if deep:
        jobs["recommendations"] = lambda: recommend.recommendations(gcp, pid, limit=15)
        jobs["service_accounts"] = lambda: iam.service_accounts(gcp, pid)
    started = now_utc()
    got, errors = sections(jobs, workers=10)
    # Trim bulky sections for the reply; the dedicated tools give full detail.
    acc = got.get("access")
    if acc:
        acc.pop("all", None)
    act = got.get("activity")
    if act:
        act["items"] = act.get("items", [])[:15]
    out: dict[str, Any] = {
        "project_id": pid,
        "generated_at": iso(started),
        "seconds": round((now_utc() - started).total_seconds(), 1),
        "findings": _findings(got),
        **got,
    }
    if errors:
        out["unavailable"] = errors
    out["next"] = (
        "for detail use skywalker_spend, skywalker_compute, skywalker_access, skywalker_exposure, "
        "skywalker_recommendations, skywalker_activity; deep=true adds recommendations and SA keys"
    )
    return out


# --- Fleet ----------------------------------------------------------------------


def fleet(gcp: Gcp, cfg: IntelConfig, limit: int = 25) -> dict[str, Any]:
    """Across every project in the configured folders: spend leaders, risers,
    budgets in trouble, running VMs and GPUs, public exposure."""
    lim = clamp(limit, 1, 200)
    scopes = cfg.fleet_scopes

    def running_vms() -> dict[str, Any]:
        per: dict[str, dict[str, Any]] = {}
        for sc in scopes:
            for r in gcp.paged(
                f"{ASSET}/{sc}:searchAllResources",
                {
                    "assetTypes": "compute.googleapis.com/Instance",
                    "query": "state:RUNNING",
                    "readMask": "name,project,location,additionalAttributes",
                },
                "results",
                limit=5000,
            ):
                proj = r.get("name", "").split("/projects/")[-1].split("/")[0]
                a = r.get("additionalAttributes", {}) or {}
                mt = str(a.get("machineType", ""))
                e = per.setdefault(
                    proj,
                    {
                        "project_id": proj,
                        "running": 0,
                        "gpu_like": 0,
                        "machine_types": {},
                    },
                )
                e["running"] += 1
                e["machine_types"][mt] = e["machine_types"].get(mt, 0) + 1
                if mt.split("-")[0] in ("a2", "a3", "a4", "g2", "g4") or "gpu" in mt:
                    e["gpu_like"] += 1
        rows = sorted(per.values(), key=lambda x: -x["running"])
        return {
            "projects_with_running_vms": len(rows),
            "running_vms": sum(r["running"] for r in rows),
            "top": rows[:lim],
        }

    def public() -> list[dict[str, Any]]:
        out = []
        for sc in scopes:
            for r in gcp.paged(
                f"{ASSET}/{sc}:searchAllIamPolicies",
                {"query": "memberTypes:(allUsers OR allAuthenticatedUsers)"},
                "results",
                limit=500,
            ):
                out.append(
                    {
                        "resource": r.get("resource", "").replace("//", ""),
                        "project": r.get("project", ""),
                    }
                )
        return out[:lim]

    jobs: dict[str, Any] = {}
    if scopes:
        jobs["compute"] = running_vms
        jobs["public_access"] = public
    if cfg.billing_table:
        jobs["spend_by_project"] = lambda: billing.spend(
            gcp, cfg, "", "project", limit=lim
        )
        jobs["trend"] = lambda: billing.trend(gcp, cfg, "", top_n=lim)
    if cfg.billing_account:
        jobs["budgets"] = lambda: billing.budgets(gcp, cfg, "", "over", limit=lim)
    if not jobs:
        raise GcpError(
            "invalid", "no fleet scope, billing table or billing account configured"
        )
    started = now_utc()
    got, errors = sections(jobs, workers=6)
    b = got.get("budgets") or {}
    findings = []
    if b:
        s = b.get("summary", {})
        findings.append(
            f"{s.get('budgets')} budgets: {s.get('over_100pct')} over 100%, "
            f"{s.get('75_to_100pct')} at 75-100%, {s.get('unbudgeted_spenders')} spenders without a budget"
        )
    sp = got.get("spend_by_project") or {}
    if sp:
        findings.append(
            f"{sp['window']['label']}: ${sp['total']['gross']:,.0f} gross, ${sp['total']['net']:,.0f} net across the account"
        )
    tr = got.get("trend") or {}
    for r in (tr.get("rising") or [])[:3]:
        if r["change"] > 100:
            findings.append(
                f"rising: {r['project_id']} ${r['gross_last7']:,.0f} last 7d vs ${r['gross_prev7']:,.0f}"
            )
    cp = got.get("compute") or {}
    if cp:
        findings.append(
            f"{cp['running_vms']} VMs running in {cp['projects_with_running_vms']} projects"
        )
    if got.get("public_access"):
        findings.append(f"{len(got['public_access'])} resources grant public access")
    out = {
        "scopes": list(scopes),
        "generated_at": iso(started),
        "seconds": round((now_utc() - started).total_seconds(), 1),
        "findings": findings,
        **got,
    }
    if errors:
        out["unavailable"] = errors
    return out
