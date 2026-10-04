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
from access import GuardedMCP, read_only

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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("skywalker-mcp")

# Bump when a tool is added or removed or a result shape changes in a way a
# program client would notice. Reported by GET /health.
TOOLS_VERSION = "1"

# Results larger than this are cut and marked truncated (a model's context is
# the scarce resource; every tool also has its own `limit`).
MAX_RESULT_CHARS = 120_000

CONFIG = IntelConfig.from_env()

INSTRUCTIONS = (
    "Skywalker answers 'what is happening in this Google Cloud project?' for UCR "
    "Research Computing (Ursa Major lab projects are named ucr-ursa-major-<lab>). It "
    "reads Google Cloud as the signed-in person and never changes anything. Start "
    "with skywalker_overview for one project (findings first, details attached) or "
    "skywalker_fleet for every project (staff). Use skywalker_projects to find a "
    "project id by name. Money: 'gross' is usage before credits, 'net' after the "
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
        }
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker projects"))
async def skywalker_projects(
    query: str = "", limit: int = 100, fresh: bool = False
) -> str:
    """Google Cloud projects you can see. `query` matches project id, name or a
    label (e.g. 'socal', 'lab=chen'). Use it to find the exact project id."""
    return await _run(
        "projects",
        {"q": query, "l": limit},
        lambda g: projects.list_projects(g, query, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker overview"))
async def skywalker_overview(
    project_id: str, deep: bool = False, fresh: bool = False
) -> str:
    """What is happening in one project right now, in one call: findings first
    (alerts, warnings, notes), then spend this month and the 7-day trend, budget
    status, running VMs and GPUs, idle disks and IPs, enabled APIs and their traffic,
    who has access (risky grants flagged), public exposure and open firewall ports,
    Security Command Center findings, API keys, and the last 7 days of admin
    changes. deep=true adds Google's recommendations and service-account key ages
    (slower)."""
    return await _run(
        "overview",
        {"p": project_id, "d": deep},
        lambda g: overview.overview(g, CONFIG, project_id, deep),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker spend"))
async def skywalker_spend(
    project_id: str,
    group_by: str = "service",
    days: int = 0,
    month: str = "",
    limit: int = 25,
    fresh: bool = False,
) -> str:
    """Spend for one project from the Cloud Billing export: gross, credits and net.
    group_by: service, sku, day, region. Window: month to date by default; days=N
    for the last N days; month='2026-09' for a whole month."""
    if group_by in ("project", "label_lab"):
        raise ToolError("cross-project grouping is skywalker_spend_all (staff)")
    return await _run(
        "spend",
        {"p": project_id, "g": group_by, "d": days, "m": month, "l": limit},
        lambda g: billing.spend(g, CONFIG, project_id, group_by, days, month, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker budget"))
async def skywalker_budget(project_id: str, fresh: bool = False) -> str:
    """The project's budget(s): amount, period, thresholds, throttle topic, this
    month's spend against it and the 7-day daily rate. Needs Billing Account
    Viewer (or budget access) on the billing account."""
    return await _run(
        "budget",
        {"p": project_id},
        lambda g: billing.budgets(g, CONFIG, project_id),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker inventory"))
async def skywalker_inventory(
    project_id: str, asset_type: str = "", limit: int = 50, fresh: bool = False
) -> str:
    """Everything in a project from Cloud Asset Inventory, every region: counts by
    type and location. asset_type lists those resources, e.g. 'bucket', 'vm',
    'cloud_run_service', 'cloud_sql', 'gke_cluster', or a full type such as
    'compute.googleapis.com/Instance'."""
    return await _run(
        "inventory",
        {"p": project_id, "t": asset_type, "l": limit},
        lambda g: inventory.inventory(g, project_id, asset_type, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker compute"))
async def skywalker_compute(
    project_id: str, limit: int = 50, fresh: bool = False
) -> str:
    """VMs (status, machine type, GPUs, spot, external IPs, how long stopped),
    disks (unattached first), static IPs, snapshots and custom images, every zone."""
    return await _run(
        "compute",
        {"p": project_id, "l": limit},
        lambda g: inventory.compute(g, project_id, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker recommendations"))
async def skywalker_recommendations(
    project_id: str, kinds: str = "", limit: int = 50, fresh: bool = False
) -> str:
    """Google's Recommender findings with monthly savings: idle VMs, disks, IPs and
    images, VM and Cloud SQL rightsizing, commitments, unattended project, and
    unused IAM roles. kinds: comma list of idle_vm, rightsize_vm, idle_disk,
    idle_ip, idle_image, idle_sql, overprovisioned_sql, commitment,
    unattended_project, iam_unused_role."""
    return await _run(
        "recommendations",
        {"p": project_id, "k": kinds, "l": limit},
        lambda g: recommend.recommendations(g, project_id, kinds, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker access"))
async def skywalker_access(
    project_id: str, principal: str = "", fresh: bool = False
) -> str:
    """Who can do what on the project (IAM policy), with risky grants flagged:
    public members, accounts outside ucr.edu, deleted principals, owner/editor and
    other admin roles, the default compute service account as editor/owner.
    principal filters by a substring of the member."""
    return await _run(
        "access",
        {"p": project_id, "m": principal},
        lambda g: iam.access(g, CONFIG, project_id, principal),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker service accounts"))
async def skywalker_service_accounts(
    project_id: str, key_age_days: int = 90, fresh: bool = False
) -> str:
    """Service accounts, their user-managed keys (age, last used) and when each
    account last authenticated (Policy Analyzer). Flags keys older than
    key_age_days and accounts unused for 90 days."""
    return await _run(
        "service_accounts",
        {"p": project_id, "a": key_age_days},
        lambda g: iam.service_accounts(g, project_id, key_age_days),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker API keys"))
async def skywalker_api_keys(
    project_id: str, days: int = 30, fresh: bool = False
) -> str:
    """API keys: restrictions (which APIs, which apps), bound service account, age,
    and requests per key and API over the last `days` (1-42). Key strings are never
    read."""
    return await _run(
        "api_keys",
        {"p": project_id, "d": days},
        lambda g: iam.api_keys(g, project_id, days),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker exposure"))
async def skywalker_exposure(project_id: str, fresh: bool = False) -> str:
    """Public exposure: resources granted to allUsers/allAuthenticatedUsers,
    firewall rules opening SSH/RDP/databases/Jupyter to the internet, VMs with
    external IPs, and active Security Command Center findings by severity."""
    return await _run(
        "exposure", {"p": project_id}, lambda g: security.exposure(g, project_id), fresh
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker activity"))
async def skywalker_activity(
    project_id: str,
    days: int = 7,
    principal: str = "",
    method_contains: str = "",
    limit: int = 50,
    fresh: bool = False,
) -> str:
    """Admin Activity audit log: who created, deleted, started, stopped or changed
    what, newest first, with counts by person and method. Filter by principal
    (email substring) or method_contains (e.g. 'delete', 'SetIamPolicy', 'start')."""
    return await _run(
        "activity",
        {"p": project_id, "d": days, "w": principal, "m": method_contains, "l": limit},
        lambda g: ops.activity(g, project_id, days, principal, method_contains, limit),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker services"))
async def skywalker_services(project_id: str, fresh: bool = False) -> str:
    """Enabled APIs on the project, with the ones that usually cost money or deserve
    a look (Vertex AI, Gemini API, Compute, GKE, Filestore, ...) listed first."""
    return await _run(
        "services",
        {"p": project_id},
        lambda g: ops.enabled_services(g, project_id),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker API traffic"))
async def skywalker_api_traffic(
    project_id: str, days: int = 7, service: str = "", fresh: bool = False
) -> str:
    """Requests per API over the last `days` (Cloud Monitoring), with error counts.
    With service (e.g. 'aiplatform'), requests per method: GenerateContent is Gemini
    on Vertex, RawPredict/StreamRawPredict is Claude or other Model Garden models."""
    return await _run(
        "api_traffic",
        {"p": project_id, "d": days, "s": service},
        lambda g: ops.api_traffic(g, project_id, days, service),
        fresh,
    )


@mcp.guarded_tool(role="read", annotations=read_only("Skywalker quotas"))
async def skywalker_quotas(
    project_id: str, service: str = "compute.googleapis.com", fresh: bool = False
) -> str:
    """Quota usage vs limit by region (near-limit flagged) and GPU quota limits for
    a service (default Compute Engine)."""
    return await _run(
        "quotas",
        {"p": project_id, "s": service},
        lambda g: ops.quotas(g, project_id, service),
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
