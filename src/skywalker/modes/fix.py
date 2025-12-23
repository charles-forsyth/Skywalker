import argparse
import contextlib
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from ..logger import logger
from ..walkers import monitoring


def _install_agent(instance: dict[str, Any]) -> str:
    """Installs Ops Agent via SSH."""
    name = instance.get("instance_name")
    zone = instance.get("zone")
    project = instance.get("project_id")

    if not name or not zone or not project or name == "unknown":
        return f"[yellow]Skipping {name}: Missing details[/yellow]"

    # Safety: Skip GKE nodes
    if name.startswith("gke-"):
        return f"[yellow]Skipping {name}: GKE Node (COS not supported)[/yellow]"

    cmd_str = (
        "curl -sSO https://dl.google.com/cloudagents/"
        "add-google-cloud-ops-agent-repo.sh && "
        "sudo bash add-google-cloud-ops-agent-repo.sh --also-install"
    )

    ssh_cmd = [
        "gcloud",
        "compute",
        "ssh",
        name,
        "--zone",
        zone,
        "--project",
        project,
        "--command",
        cmd_str,
        "--quiet",
        "--tunnel-through-iap",
    ]

    try:
        res = subprocess.run(ssh_cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return f"[green]SUCCESS: {name}[/green]"
        err = res.stderr.strip().splitlines()[-1] if res.stderr else "Unknown error"
        return f"[red]FAILED: {name} - {err}[/red]"
    except Exception as e:
        return f"[red]ERROR: {name} - {e}[/red]"


def _fix_ops_agent(args: argparse.Namespace, console: Console) -> None:
    """Finds and fixes instances missing the Ops Agent."""
    if not args.monitor:
        console.print("[red]Error: --fix ops-agent currently requires --monitor[/red]")
        return

    # 1. Discovery
    console.print("Scanning fleet for missing agents...")
    scoping_proj = args.scoping_project or "ucr-research-computing"

    try:
        metrics = monitoring.fetch_fleet_metrics(scoping_proj)
    except Exception as e:
        console.print(f"[red]Failed to fetch metrics: {e}[/red]")
        return

    # 2. Filter Candidates
    # Criteria: Running (CPU > 0), Missing Memory (mem is None/NaN), Not GKE
    candidates = []

    # REFACTOR: We need the asset enrichment logic here.
    # It's better to import the enrichment logic or re-implement it briefly.

    # We need to resolve names.
    from ..walkers import asset

    projects_to_scan = {m.get("project_id") for m in metrics if m.get("project_id")}
    console.print(f"Resolving names for {len(projects_to_scan)} projects...")

    assets = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(asset.search_all_instances, f"projects/{pid}"): pid
            for pid in projects_to_scan
        }
        for future in as_completed(futures):
            with contextlib.suppress(Exception):
                assets.update(future.result())

    # Now filter
    for m in metrics:
        iid = str(m.get("instance_id", ""))
        cpu = m.get("cpu_percent", 0)
        mem = m.get("memory_percent")

        if iid in assets:
            m["instance_name"] = assets[iid]["name"]
            m["machine_type"] = assets[iid]["machine_type"]
        else:
            m["instance_name"] = "unknown"

        name = m.get("instance_name", "unknown")

        # Logic: CPU active (>0.1%), Memory MISSING, Name known, Not GKE
        if (
            cpu > 0.1
            and mem is None
            and name != "unknown"
            and not name.startswith("gke-")
        ):
            candidates.append(m)

    if not candidates:
        console.print(
            "[green]No candidates found! All eligible VMs have Ops Agent.[/green]"
        )
        return

    # 3. Present List
    table = Table(title=f"Ops Agent Install Candidates ({len(candidates)})")
    table.add_column("Project", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Zone")
    table.add_column("CPU %")

    for c in candidates:
        table.add_row(
            c.get("project_id"),
            c.get("instance_name"),
            c.get("zone"),
            f"{c.get('cpu_percent', 0):.1f}%",
        )

    console.print(table)

    # 4. Confirm
    if not Confirm.ask(f"Install Ops Agent on these {len(candidates)} instances?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    # 5. Execute
    console.print("Launching installers (this may take a minute)...")
    from concurrent.futures import Future
    with ThreadPoolExecutor(max_workers=10) as executor:
        install_futures: list[Future[str]] = [
            executor.submit(_install_agent, c) for c in candidates
        ]
        for future in as_completed(install_futures):
            console.print(future.result())


def run_fix(
    args: argparse.Namespace, _log_console: Console, out_console: Console
) -> None:
    """Dispatcher for fix commands."""
    if args.fix == "ops-agent":
        _fix_ops_agent(args, out_console)
    else:
        logger.error(f"Unknown fix type: {args.fix}")
