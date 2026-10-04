"""
Skywalker MCP server: what is happening in our Google Cloud projects.

Every tool acts on Google Cloud as the signed-in caller (their own Google token),
so it sees only what that person's account can see, and Google's audit logs name
them. Every tool only reads; `skywalker.intel.gcp` refuses any request that could
change something before it leaves the process.

Roles (users.yaml): `read` gets the per-project tools; `staff` adds the account-
and fleet-wide ones (spend across projects, every budget, fleet overview), which
cost more to run. app.py adds Google sign-in, Streamable HTTP at /mcp and the
legacy SSE transport at /sse.

Project scope (scope.py): a `read` user may ask only about the projects listed for
them in users.yaml; staff and admins may ask about anything their Google account
can see. `project_id` is optional on every per-project tool: it defaults to the
caller's focus (`skywalker_focus`), which starts at their first listed project.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Callable
from typing import Any

import anyio.to_thread
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import cache
import scope
from access import GuardedMCP, read_only, setting
from users import default_project, project_allowed

from skywalker.intel import (
    GcpError,
    IntelConfig,
    billing,
    iam,
    inventory,
    ops,
    overview,
    projects,
    recommend,
    security,
)
from skywalker.intel.util import project_id as valid_project_id

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("skywalker-mcp")

# Bump when a tool is added or removed or a result shape changes in a way a
# program client would notice. Reported by GET /health.
TOOLS_VERSION = "2"

# Results larger than this are cut and marked truncated (a model's context is
# the scarce resource; every tool also has its own `limit`).
MAX_RESULT_CHARS = 120_000

CONFIG = IntelConfig.from_env()

INSTRUCTIONS = (
    "Skywalker answers 'what is happening in this Google Cloud project?' for UCR "
    "Research Computing (Ursa Major lab projects are named ucr-ursa-major-<lab>). It "
    "reads Google Cloud as the signed-in person and never changes anything. Start "
    "with skywalker_overview for one project (findings first, details attached) or "
    "skywalker_fleet for every project (staff). project_id is optional: it defaults "
    "to the caller's focus; skywalker_focus shows or changes it (staff can focus on "
    "'all'). Use skywalker_projects to find a project id by name. Money: 'gross' is usage before credits, 'net' after the "
    "PSSA subscription credits; lab budgets count gross. Recommendation savings are "
    "Google's list-price projections. Each answer is cached for 2 minutes per "
    "person; pass fresh=true to re-read."
)

mcp = GuardedMCP(
    "Skywalker",
    instructions=INSTRUCTIONS,
    stateless_http=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


def _shrink(value: Any) -> str:
    text = json.dumps(value, default=str, separators=(",", ":"))
    if len(text) <= MAX_RESULT_CHARS:
        return text
    return json.dumps(
        {
            "truncated": True,
            "note": f"result was {len(text)} characters; showing the start. Use a "
            "narrower tool or a smaller limit for the rest.",
            "partial": text[: MAX_RESULT_CHARS - 300],
        }
    )


def _ident() -> Any:
    ident = mcp.identity()
    if ident is None:
        raise ToolError("not signed in")
    return ident


def _pid(project_id: str, allow_all: bool = False) -> str:
    """The project this call is about (focus when empty); read users are held to
    their own projects here, before any Google call."""
    return scope.resolve(_ident(), mcp.store, project_id, allow_all)


async def _run(
    tool: str, args: dict[str, Any], fn: Callable[..., Any], fresh: bool = False
) -> str:
    """Run a blocking intel call as the caller, cached per person + client."""
    ident = mcp.identity()
    if ident is None:
        raise ToolError("not signed in")
    gcp = mcp.caller_gcp(ident)

    async def go() -> Any:
        return await anyio.to_thread.run_sync(lambda: fn(gcp))

    k = cache.key(ident.email, ident.client_id, tool, args)
    try:
        result = await cache.cached(k, go, fresh=fresh)
    except GcpError as e:
        # A real MCP error (isError) with a short, actionable reason.
        raise ToolError(f"{e.kind}: {str(e)[:400]}") from e
    return _shrink(result)


# --- Read: anyone on the access list (bounded by their own Google access) -----------


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker whoami"))
async def skywalker_whoami() -> str:
    """Who you are signed in as: email, role, client, and whether Skywalker holds a
    working Google token for you (it reads Google Cloud as you)."""
    ident = mcp.identity()
    if ident is None:
        raise ToolError("not signed in")
    tokens = mcp.google_tokens
    ok, why = False, ""
    if tokens is not None:
        try:
            await anyio.to_thread.run_sync(lambda: tokens.access_token(ident.email))
            ok = True
        except Exception as e:
            why = str(e)
    return json.dumps(
        {
            **ident.as_dict(),
            "google_token_ok": ok,
            "google_problem": why or None,
            "tools_version": TOOLS_VERSION,
            "billing_export": bool(CONFIG.billing_table),
            "fleet_scopes": list(CONFIG.fleet_scopes),
            "focus": scope.focus(mcp.store, ident) or None,
            "project_rule": "any project your Google account can see"
            if scope.is_staff(ident)
            else "only your listed projects",
        }
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker projects"))
async def skywalker_projects(
    query: str = "", limit: int = 100, fresh: bool = False
) -> str:
    """Google Cloud projects you can see. `query` matches project id, name or a
    label (e.g. 'socal', 'lab=chen'). Use it to find the exact project id. For a
    read user, only their own Skywalker projects are listed."""
    ident = _ident()
    if scope.is_staff(ident):
        return await _run(
            "projects",
            {"q": query, "l": limit},
            lambda g: projects.list_projects(g, query, limit),
            fresh,
        )

    def mine(g: Any) -> Any:
        out = projects.list_projects(g, query, 1000)
        rows = [
            p
            for p in out["projects"]
            if project_allowed(ident.projects, p["project_id"])
        ]
        by_parent: dict[str, int] = {}
        for p in rows:
            by_parent[p["parent"]] = by_parent.get(p["parent"], 0) + 1
        n = max(1, min(limit, 1000))
        return {
            "total": len(rows),
            "by_parent": by_parent,
            "projects": rows[:n],
            "truncated": len(rows) > n,
            "note": "your Skywalker projects: " + ", ".join(ident.projects),
        }

    return await _run("projects", {"q": query, "l": limit}, mine, fresh)


@mcp.guarded_tool(role="read", annotations=setting("Skywalker focus"))
async def skywalker_focus(project_id: str = "", reset: bool = False) -> str:
    """Show or set your focus: the project every tool uses when you don't name one.
    Shared by all your clients (Claude, Hermes, Gemini Enterprise). Staff and
    admins may focus on any project their Google account can see, or 'all' (then
    skywalker_overview is the fleet view). A read user may switch between their own
    projects. reset=true goes back to your default (first listed project). This
    only changes a Skywalker setting; nothing in Google Cloud changes."""
    ident = _ident()
    store = mcp.store
    if store is None:
        raise ToolError("server has no store for settings")
    pid = (project_id or "").strip().lower()
    if reset:
        scope.clear_focus(store, ident)
    elif pid:
        if pid == scope.ALL:
            if not scope.is_staff(ident):
                raise ToolError(
                    "'all' is for staff; you can focus on one of your projects."
                )
        else:
            try:
                valid_project_id(pid)
            except GcpError as e:
                raise ToolError(str(e)) from e
            scope.check_allowed(ident, pid)
        scope.set_focus(store, ident, pid)
    return json.dumps(
        {
            "focus": scope.focus(store, ident) or None,
            "default": default_project(ident.projects) or None,
            "your_projects": list(ident.projects),
            "rule": "staff/admin: any project your Google account can see, or 'all'"
            if scope.is_staff(ident)
            else "read: only your listed projects",
        }
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker overview"))
async def skywalker_overview(
    project_id: str = "", deep: bool = False, fresh: bool = False
) -> str:
    """What is happening in one project right now, in one call: findings first
    (alerts, warnings, notes), then spend this month and the 7-day trend, budget
    status, running VMs and GPUs, idle disks and IPs, enabled APIs and their traffic,
    who has access (risky grants flagged), public exposure and open firewall ports,
    Security Command Center findings, API keys, and the last 7 days of admin
    changes. deep=true adds Google's recommendations and service-account key ages
    (slower). With no project_id it uses your focus; a staff focus of 'all' gives
    the fleet view."""
    pid = _pid(project_id, allow_all=True)
    if pid == scope.ALL:
        # Focus 'all' (staff): the fleet view instead of one project.
        return await _run(
            "fleet", {"l": 25}, lambda g: overview.fleet(g, CONFIG, 25), fresh
        )
    return await _run(
        "overview",
        {"p": pid, "d": deep},
        lambda g: overview.overview(g, CONFIG, pid, deep),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker spend"))
async def skywalker_spend(
    project_id: str = "",
    group_by: str = "service",
    days: int = 0,
    month: str = "",
    limit: int = 25,
    fresh: bool = False,
) -> str:
    """Spend for one project from the Cloud Billing export: gross, credits and net.
    group_by: service, sku, day, region. Window: month to date by default; days=N
    for the last N days; month='2026-09' for a whole month."""
    pid = _pid(project_id)
    if group_by in ("project", "label_lab"):
        raise ToolError("cross-project grouping is skywalker_spend_all (staff)")
    return await _run(
        "spend",
        {"p": pid, "g": group_by, "d": days, "m": month, "l": limit},
        lambda g: billing.spend(g, CONFIG, pid, group_by, days, month, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker budget"))
async def skywalker_budget(project_id: str = "", fresh: bool = False) -> str:
    """The project's budget(s): amount, period, thresholds, throttle topic, this
    month's spend against it and the 7-day daily rate. Needs Billing Account
    Viewer (or budget access) on the billing account."""
    pid = _pid(project_id)
    return await _run(
        "budget",
        {"p": pid},
        lambda g: billing.budgets(g, CONFIG, pid),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker inventory"))
async def skywalker_inventory(
    project_id: str = "", asset_type: str = "", limit: int = 50, fresh: bool = False
) -> str:
    """Everything in a project from Cloud Asset Inventory, every region: counts by
    type and location. asset_type lists those resources, e.g. 'bucket', 'vm',
    'cloud_run_service', 'cloud_sql', 'gke_cluster', or a full type such as
    'compute.googleapis.com/Instance'."""
    pid = _pid(project_id)
    return await _run(
        "inventory",
        {"p": pid, "t": asset_type, "l": limit},
        lambda g: inventory.inventory(g, pid, asset_type, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker compute"))
async def skywalker_compute(
    project_id: str = "", limit: int = 50, fresh: bool = False
) -> str:
    """VMs (status, machine type, GPUs, spot, external IPs, how long stopped),
    disks (unattached first), static IPs, snapshots and custom images, every zone."""
    pid = _pid(project_id)
    return await _run(
        "compute",
        {"p": pid, "l": limit},
        lambda g: inventory.compute(g, pid, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker recommendations"))
async def skywalker_recommendations(
    project_id: str = "", kinds: str = "", limit: int = 50, fresh: bool = False
) -> str:
    """Google's Recommender findings with monthly savings: idle VMs, disks, IPs and
    images, VM and Cloud SQL rightsizing, commitments, unattended project, and
    unused IAM roles. kinds: comma list of idle_vm, rightsize_vm, idle_disk,
    idle_ip, idle_image, idle_sql, overprovisioned_sql, commitment,
    unattended_project, iam_unused_role."""
    pid = _pid(project_id)
    return await _run(
        "recommendations",
        {"p": pid, "k": kinds, "l": limit},
        lambda g: recommend.recommendations(g, pid, kinds, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker access"))
async def skywalker_access(
    project_id: str = "", principal: str = "", fresh: bool = False
) -> str:
    """Who can do what on the project (IAM policy), with risky grants flagged:
    public members, accounts outside ucr.edu, deleted principals, owner/editor and
    other admin roles, the default compute service account as editor/owner.
    principal filters by a substring of the member."""
    pid = _pid(project_id)
    return await _run(
        "access",
        {"p": pid, "m": principal},
        lambda g: iam.access(g, CONFIG, pid, principal),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker service accounts"))
async def skywalker_service_accounts(
    project_id: str = "", key_age_days: int = 90, fresh: bool = False
) -> str:
    """Service accounts, their user-managed keys (age, last used) and when each
    account last authenticated (Policy Analyzer). Flags keys older than
    key_age_days and accounts unused for 90 days."""
    pid = _pid(project_id)
    return await _run(
        "service_accounts",
        {"p": pid, "a": key_age_days},
        lambda g: iam.service_accounts(g, pid, key_age_days),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker API keys"))
async def skywalker_api_keys(
    project_id: str = "", days: int = 30, fresh: bool = False
) -> str:
    """API keys: restrictions (which APIs, which apps), bound service account, age,
    and requests per key and API over the last `days` (1-42). Key strings are never
    read."""
    pid = _pid(project_id)
    return await _run(
        "api_keys",
        {"p": pid, "d": days},
        lambda g: iam.api_keys(g, pid, days),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker exposure"))
async def skywalker_exposure(project_id: str = "", fresh: bool = False) -> str:
    """Public exposure: resources granted to allUsers/allAuthenticatedUsers,
    firewall rules opening SSH/RDP/databases/Jupyter to the internet, VMs with
    external IPs, and active Security Command Center findings by severity."""
    pid = _pid(project_id)
    return await _run(
        "exposure", {"p": pid}, lambda g: security.exposure(g, pid), fresh
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker activity"))
async def skywalker_activity(
    project_id: str = "",
    days: int = 7,
    principal: str = "",
    method_contains: str = "",
    limit: int = 50,
    fresh: bool = False,
) -> str:
    """Admin Activity audit log: who created, deleted, started, stopped or changed
    what, newest first, with counts by person and method. Filter by principal
    (email substring) or method_contains (e.g. 'delete', 'SetIamPolicy', 'start')."""
    pid = _pid(project_id)
    return await _run(
        "activity",
        {"p": pid, "d": days, "w": principal, "m": method_contains, "l": limit},
        lambda g: ops.activity(g, pid, days, principal, method_contains, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker services"))
async def skywalker_services(project_id: str = "", fresh: bool = False) -> str:
    """Enabled APIs on the project, with the ones that usually cost money or deserve
    a look (Vertex AI, Gemini API, Compute, GKE, Filestore, ...) listed first."""
    pid = _pid(project_id)
    return await _run(
        "services",
        {"p": pid},
        lambda g: ops.enabled_services(g, pid),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker API traffic"))
async def skywalker_api_traffic(
    project_id: str = "", days: int = 7, service: str = "", fresh: bool = False
) -> str:
    """Requests per API over the last `days` (Cloud Monitoring), with error counts.
    With service (e.g. 'aiplatform'), requests per method: GenerateContent is Gemini
    on Vertex, RawPredict/StreamRawPredict is Claude or other Model Garden models."""
    pid = _pid(project_id)
    return await _run(
        "api_traffic",
        {"p": pid, "d": days, "s": service},
        lambda g: ops.api_traffic(g, pid, days, service),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker quotas"))
async def skywalker_quotas(
    project_id: str = "", service: str = "compute.googleapis.com", fresh: bool = False
) -> str:
    """Quota usage vs limit by region (near-limit flagged) and GPU quota limits for
    a service (default Compute Engine)."""
    pid = _pid(project_id)
    return await _run(
        "quotas",
        {"p": pid, "s": service},
        lambda g: ops.quotas(g, pid, service),
        fresh,
    )


# --- Staff: account- and fleet-wide (cost more to run) ------------------------------


@mcp.guarded_tool(role="staff", annotations=read_only("Skywalker fleet"))
async def skywalker_fleet(limit: int = 25, fresh: bool = False) -> str:
    """[staff] Every project at once: month-to-date spend by project, who is speeding
    up (7 days vs the 7 before), budgets over 100% and spenders with no budget,
    running VMs (and GPU machine types) by project, and resources granted public
    access."""
    return await _run(
        "fleet", {"l": limit}, lambda g: overview.fleet(g, CONFIG, limit), fresh
    )


@mcp.guarded_tool(role="staff", annotations=read_only("Skywalker spend all"))
async def skywalker_spend_all(
    group_by: str = "project",
    days: int = 0,
    month: str = "",
    limit: int = 50,
    fresh: bool = False,
) -> str:
    """[staff] Spend across the whole billing account. group_by: project, service,
    sku, day, region, label_lab. Window as skywalker_spend."""
    return await _run(
        "spend_all",
        {"g": group_by, "d": days, "m": month, "l": limit},
        lambda g: billing.spend(g, CONFIG, "", group_by, days, month, limit),
        fresh,
    )


@mcp.guarded_tool(role="staff", annotations=read_only("Skywalker budgets"))
async def skywalker_budgets(
    status: str = "", limit: int = 50, fresh: bool = False
) -> str:
    """[staff] Every budget on the billing account with this month's spend and %:
    status='over' (>=100%), 'warn' (75-99%), 'unbudgeted' (spenders with no budget),
    or empty for all. Also counts silenced high caps, duplicate budgets and budgets
    with no Pub/Sub throttle."""
    return await _run(
        "budgets",
        {"s": status, "l": limit},
        lambda g: billing.budgets(g, CONFIG, "", status, limit),
        fresh,
    )


@mcp.guarded_tool(role="staff", annotations=read_only("Skywalker spend trend"))
async def skywalker_spend_trend(top_n: int = 20, fresh: bool = False) -> str:
    """[staff] Which projects are speeding up or slowing down: gross spend in the last
    7 days vs the 7 before, per project, plus account-level charges."""
    return await _run(
        "spend_trend",
        {"n": top_n},
        lambda g: billing.trend(g, CONFIG, "", top_n),
        fresh,
    )


if __name__ == "__main__":
    print(
        "Run app.py (Cloud Run) or tests; Skywalker has no stdio mode.", file=sys.stderr
    )
    sys.exit(2)
