import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from importlib.metadata import version
from typing import Any, cast

import humanize
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .core import STANDARD_REGIONS, ZONE_SUFFIXES
from .schemas.compute import GCPComputeInstance, GCPComputeReport
from .schemas.gke import GCPCluster
from .schemas.run import GCPCloudRunService
from .schemas.vertex import GCPVertexReport
from .users import UserResolver
from .walkers import compute, gke, iam, network, org, run, sql, storage, vertex


def scan_compute_zone(
    project_id: str, zone: str, include_metrics: bool = False
) -> list[GCPComputeInstance]:
    try:
        return cast(
            list[GCPComputeInstance],
            compute.list_instances(
                project_id=project_id, zone=zone, include_metrics=include_metrics
            ),
        )
    except Exception:
        return []


def scan_run_region(project_id: str, region: str) -> list[GCPCloudRunService]:
    try:
        return cast(
            list[GCPCloudRunService],
            run.list_services(project_id=project_id, region=region),
        )
    except Exception:
        return []


def scan_gke_location(project_id: str, location: str) -> list[GCPCluster]:
    try:
        return cast(
            list[GCPCluster],
            gke.list_clusters(project_id=project_id, location=location),
        )
    except Exception:
        return []


def scan_vertex_location(project_id: str, location: str) -> GCPVertexReport:
    try:
        return cast(
            GCPVertexReport,
            vertex.get_vertex_report(project_id=project_id, location=location),
        )
    except Exception:
        return GCPVertexReport()


def run_audit_for_project(
    project_id: str,
    services: list[str],
    regions: list[str],
    console: Console,
    include_metrics: bool = False,
) -> dict[str, Any]:
    """
    Executes all requested walkers for a single project and returns the combined data.
    """
    report_data: dict[str, Any] = {
        "project_id": project_id,
        "scan_time": datetime.now(timezone.utc),
        "services": {},
    }

    # --- Compute Engine (Zonal + Global) ---
    if "compute" in services:
        compute_report = GCPComputeReport()

        # 1. Instances (Zonal)
        target_zones = [f"{r}-{s}" for r in regions for s in ZONE_SUFFIXES]
        with ThreadPoolExecutor(max_workers=10) as compute_executor:
            future_to_zone = {
                compute_executor.submit(
                    scan_compute_zone, project_id, z, include_metrics
                ): z
                for z in target_zones
            }
            for compute_future in as_completed(future_to_zone):
                compute_report.instances.extend(compute_future.result())

        # 2. Images & Snapshots (Global/Project-level)
        try:
            compute_report.images = compute.list_images(project_id)
            compute_report.machine_images = compute.list_machine_images(project_id)
            compute_report.snapshots = compute.list_snapshots(project_id)
        except Exception as e:
            console.print(
                f"[yellow]Warning: Failed to list images/snapshots: {e}[/yellow]"
            )

        report_data["services"]["compute"] = compute_report

    # --- Cloud Run (Regional) ---
    if "run" in services:
        run_results = []
        with ThreadPoolExecutor(max_workers=len(regions)) as executor:
            futures = [executor.submit(scan_run_region, project_id, r) for r in regions]
            for future in as_completed(futures):
                run_results.extend(future.result())
        report_data["services"]["run"] = run_results

    # --- GKE (Regional) ---
    if "gke" in services:
        gke_results = []
        with ThreadPoolExecutor(max_workers=len(regions)) as gke_executor:
            gke_futures = [
                gke_executor.submit(scan_gke_location, project_id, r) for r in regions
            ]
            for gke_future in as_completed(gke_futures):
                gke_results.extend(gke_future.result())
        report_data["services"]["gke"] = gke_results

    # --- IAM (Global) ---
    if "iam" in services:
        iam_res = iam.get_iam_report(project_id)
        # Resolve names early for all reports
        resolver = UserResolver()
        for binding in iam_res.policy_bindings:
            if "roles/owner" in binding.role:
                for user in binding.categorized_members["users"]:
                    display_name = resolver.get_display_name(user)
                    if display_name:
                        iam_res.user_display_names[user] = display_name
        report_data["services"]["iam"] = iam_res

    # --- Cloud SQL (Global call) ---
    if "sql" in services:
        try:
            report_data["services"]["sql"] = sql.list_instances(project_id)
        except Exception as e:
            console.print(
                f"[yellow]Warning: SQL scan failed for {project_id}: {e}[/yellow]"
            )

    # --- Vertex AI (Regional) ---
    if "vertex" in services:
        vertex_results = GCPVertexReport()
        with ThreadPoolExecutor(max_workers=len(regions)) as vertex_executor:
            vertex_futures = [
                vertex_executor.submit(scan_vertex_location, project_id, r)
                for r in regions
            ]
            for vertex_future in as_completed(vertex_futures):
                rep = vertex_future.result()
                vertex_results.notebooks.extend(rep.notebooks)
                vertex_results.models.extend(rep.models)
                vertex_results.endpoints.extend(rep.endpoints)
        report_data["services"]["vertex"] = vertex_results

    # --- Network (Global) ---
    if "network" in services:
        try:
            report_data["services"]["network"] = network.get_network_report(project_id)
        except Exception as e:
            console.print(
                f"[yellow]Warning: Network scan failed for {project_id}: {e}[/yellow]"
            )

    # --- Cloud Storage (Global) ---
    if "storage" in services:
        try:
            report_data["services"]["storage"] = storage.list_buckets(project_id)
        except Exception as e:
            console.print(
                f"[yellow]Warning: Storage scan failed for {project_id}: {e}[/yellow]"
            )

    return report_data


def print_project_summary(data: dict[str, Any], console: Console) -> None:
    project_id = data["project_id"]
    services = data["services"]
    console.print(f"\n[bold underline]Project: {project_id}[/bold underline]")

    if "compute" in services:
        report = services["compute"]
        console.print(f" - Compute: [bold]{len(report.instances)}[/bold] VMs")
    if "storage" in services:
        console.print(
            f" - Cloud Storage: [bold]{len(services['storage'])}[/bold] buckets"
        )
    if "run" in services:
        console.print(f" - Cloud Run: [bold]{len(services['run'])}[/bold] services")
    if "gke" in services:
        console.print(f" - GKE: [bold]{len(services['gke'])}[/bold] clusters")
    if "sql" in services:
        console.print(f" - Cloud SQL: [bold]{len(services['sql'])}[/bold] instances")
    if "iam" in services:
        console.print(
            f" - IAM: [bold]{len(services['iam'].service_accounts)}[/bold] SAs, "
            f"[bold]{len(services['iam'].policy_bindings)}[/bold] Bindings"
        )
    if "network" in services:
        console.print(
            f" - Network: [bold]{len(services['network'].firewalls)}[/bold] Firewalls, "
            f"[bold]{len(services['network'].addresses)}[/bold] Static IPs"
        )


def print_project_detailed(data: dict[str, Any], console: Console) -> None:
    """Prints full resource details for a single project audit."""
    project_id = data["project_id"]
    services = data["services"]
    console.print(
        f"\n[bold green underline]DETAILED AUDIT: {project_id}[/bold green underline]"
    )

    # 1. Compute
    if "compute" in services:
        console.print("\n[bold]-- Compute Engine --[/bold]")
        report = services["compute"]

        # Instances
        console.print(f"Found [bold]{len(report.instances)}[/bold] instances:")
        for inst in report.instances:
            gpu_text = f" | {len(inst.gpus)} GPUs" if inst.gpus else ""
            disk_text = f" | {len(inst.disks)} Disks"
            ip_text = f" | IP: {inst.internal_ip or 'N/A'}"
            if inst.external_ip:
                ip_text += f" ({inst.external_ip})"

            perf_text = ""
            if inst.cpu_utilization is not None:
                color = "green" if inst.cpu_utilization < 70 else "yellow"
                if inst.cpu_utilization > 90:
                    color = "red"
                perf_text += (
                    f" | [bold {color}]CPU: {inst.cpu_utilization:.1f}%[/bold {color}]"
                )
            if inst.memory_usage is not None:
                perf_text += f" | [bold blue]Mem: {inst.memory_usage:.1f}%[/bold blue]"

            created_date = inst.creation_timestamp.strftime("%Y-%m-%d")
            created_text = f" | Created: {created_date}"
            console.print(
                f" - [green]{inst.name}[/green] ({inst.machine_type})"
                f" [{inst.status}]{created_text}{gpu_text}{disk_text}{ip_text}"
                f"{perf_text}"
            )

        # Images
        if report.images:
            console.print(f"\nFound [bold]{len(report.images)}[/bold] Custom Images:")
            for img in report.images:
                size_str = (
                    humanize.naturalsize(img.archive_size_bytes)
                    if img.archive_size_bytes
                    else "Unknown"
                )
                console.print(
                    f" - [cyan]{img.name}[/cyan] ({img.status}) | "
                    f"Size: {size_str} | Disk: {img.disk_size_gb}GB"
                )

        # Machine Images
        if report.machine_images:
            console.print(
                f"\nFound [bold]{len(report.machine_images)}[/bold] Machine Images:"
            )
            for img in report.machine_images:
                size_str = (
                    humanize.naturalsize(img.total_storage_bytes)
                    if img.total_storage_bytes
                    else "Unknown"
                )
                console.print(
                    f" - [cyan]{img.name}[/cyan] ({img.status}) | Size: {size_str}"
                )

        # Snapshots
        if report.snapshots:
            console.print(
                f"\nFound [bold]{len(report.snapshots)}[/bold] Disk Snapshots:"
            )
            for snap in report.snapshots:
                size_str = humanize.naturalsize(snap.storage_bytes)
                console.print(
                    f" - [cyan]{snap.name}[/cyan] ({snap.status}) | "
                    f"Size: {size_str} | Source Disk: {snap.disk_size_gb}GB"
                )

    # 2. Cloud Run
    if "run" in services:
        console.print("\n[bold]-- Cloud Run --[/bold]")
        run_services = services["run"]
        console.print(f"Found [bold]{len(run_services)}[/bold] services:")
        for svc in run_services:
            console.print(
                f" - [cyan]{svc.name}[/cyan] ({svc.url})\n"
                f"   Image: {svc.image}\n"
                f"   Updated: {svc.create_time.strftime('%Y-%m-%d')} "
                f"| By: {svc.last_modifier}"
            )

    # 3. GKE
    if "gke" in services:
        console.print("\n[bold]-- GKE Clusters --[/bold]")
        clusters = services["gke"]
        console.print(f"Found [bold]{len(clusters)}[/bold] clusters:")
        for cluster in clusters:
            console.print(
                f" - [cyan]{cluster.name}[/cyan] ({cluster.version}) [{cluster.status}]"
            )
            for np in cluster.node_pools:
                console.print(
                    f"   └ Node Pool: [yellow]{np.name}[/yellow] "
                    f"({np.node_count} nodes, {np.machine_type})"
                )

    # 4. IAM
    if "iam" in services:
        console.print("\n[bold]-- IAM & Security --[/bold]")
        iam_report = services["iam"]
        console.print(f"Service Accounts: {len(iam_report.service_accounts)}")
        for sa in iam_report.service_accounts:
            status = "[red]DISABLED[/red]" if sa.disabled else "[green]ACTIVE[/green]"
            keys_text = f" | {len(sa.keys)} Keys" if sa.keys else ""
            console.print(f" - {sa.email} ({sa.display_name}) {status}{keys_text}")

        console.print("Policy Highlights (Owners):")
        for binding in iam_report.policy_bindings:
            if "roles/owner" in binding.role:
                cats = binding.categorized_members
                for user in cats["users"]:
                    display_name = iam_report.user_display_names.get(user, "")
                    name_str = f" ({display_name})" if display_name else ""
                    console.print(f" - [blue]User[/blue]: {user}{name_str}")
                for sa in cats["service_accounts"]:
                    console.print(f" - [magenta]ServiceAccount[/magenta]: {sa}")

    # 5. SQL
    if "sql" in services:
        console.print("\n[bold]-- Cloud SQL --[/bold]")
        sql_instances = services["sql"]
        console.print(f"Found [bold]{len(sql_instances)}[/bold] instances:")
        for db in sql_instances:
            ip_info = f" | IP: {db.public_ip or db.private_ip or 'None'}"
            console.print(
                f" - [cyan]{db.name}[/cyan] ({db.database_version} | "
                f"{db.tier}) [{db.status}]{ip_info} | "
                f"{db.storage_limit_gb}GB"
            )

    # 6. Vertex
    if "vertex" in services:
        console.print("\n[bold]-- Vertex AI --[/bold]")
        vtx = services["vertex"]
        if vtx.notebooks:
            console.print(f"Found [bold]{len(vtx.notebooks)}[/bold] Notebooks:")
            for nb in vtx.notebooks:
                console.print(
                    f" - [cyan]{nb.display_name}[/cyan] ({nb.state}) | {nb.creator}"
                )
        if vtx.endpoints:
            console.print(f"Found [bold]{len(vtx.endpoints)}[/bold] Endpoints:")
            for ep in vtx.endpoints:
                console.print(
                    f" - [cyan]{ep.display_name}[/cyan] (Location: {ep.location})"
                )

    # 7. Network
    if "network" in services:
        console.print("\n[bold]-- Network --[/bold]")
        net = services["network"]
        console.print(f"Firewalls: {len(net.firewalls)}")
        for fw in net.firewalls:
            if "0.0.0.0/0" in fw.source_ranges:
                console.print(
                    f" - [bold red]OPEN[/bold red] {fw.name} "
                    f"({fw.direction}) -> {fw.allowed_ports}"
                )

    # 8. Storage
    if "storage" in services:
        console.print("\n[bold]-- Cloud Storage --[/bold]")
        buckets = services["storage"]
        console.print(f"Found [bold]{len(buckets)}[/bold] buckets:")
        for b in buckets:
            size_str = humanize.naturalsize(b.size_bytes) if b.size_bytes else "0 Bytes"
            pap = (
                f"[green]{b.public_access_prevention}[/green]"
                if b.public_access_prevention == "enforced"
                else f"[red]{b.public_access_prevention}[/red]"
            )
            console.print(
                f" - [cyan]{b.name}[/cyan] ({b.location}) | "
                f"Size: {size_str} | PAP: {pap}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Skywalker: GCP Audit & Reporting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit a single project (all services)
  skywalker --project-id ucr-research-computing

  # Audit specific services in a specific region
  skywalker --project-id my-project --services compute storage --regions us-west1

  # Audit ALL active projects and generate an HTML report
  skywalker --all-projects --html fleet_report.html

  # Generate a PDF report for a single project
  skywalker --project-id my-project --report audit.pdf

  # Output raw JSON data (for piping to jq)
  skywalker --project-id my-project --json

  # Force a fresh scan (ignore cache)
  skywalker --project-id my-project --no-cache
""",
    )
    try:
        ver = version("skywalker")
    except Exception:
        ver = "unknown"
    parser.add_argument("--version", action="version", version=f"Skywalker v{ver}")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--project-id", help="GCP Project ID to scan")
    group.add_argument(
        "--all-projects",
        action="store_true",
        help="Scan all ACTIVE projects in the organization",
    )

    parser.add_argument(
        "--regions",
        nargs="+",
        default=STANDARD_REGIONS,
        help=f"Regions to scan (default: {', '.join(STANDARD_REGIONS)})",
    )

    parser.add_argument(
        "--services",
        nargs="+",
        default=["all"],
        choices=[
            "compute",
            "storage",
            "gke",
            "vertex",
            "sql",
            "iam",
            "run",
            "network",
            "all",
        ],
        help="List of services to audit (default: all)",
    )

    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--metrics", action="store_true", help="Include performance metrics (CPU/Mem)"
    )
    parser.add_argument("--report", "--pdf", dest="report", help="Output report to PDF")
    parser.add_argument("--html", help="Output report to an HTML file")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of projects to scan in parallel (default: 5)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable and clear local cache for this run",
    )

    args = parser.parse_args()

    # Handle Version check (if required=False wasn't enough)
    # The action="version" handles exit automatically if --version is passed.

    # Must validate required args manually since group is now optional for --version
    if not args.project_id and not args.all_projects:
        parser.error("one of the arguments --project-id --all-projects is required")

    # Use stderr for logs/progress if stdout is piped for JSON
    log_console = Console(stderr=True, quiet=args.json)
    out_console = Console(quiet=args.json)

    log_console.print(
        "[bold green]Skywalker[/bold green] Ursa Major Auditor initialized."
    )

    if args.no_cache:
        from .core import memory

        log_console.print("[yellow]Clearing local cache...[/yellow]")
        memory.clear(warn=False)

    services = args.services
    if "all" in services:
        services = [
            "compute",
            "storage",
            "gke",
            "vertex",
            "sql",
            "iam",
            "run",
            "network",
        ]

    # 1. Discover Projects
    target_projects = []
    if args.all_projects:
        log_console.print("Discovering ACTIVE projects...")
        target_projects = org.list_all_projects()
        log_console.print(f"Found [bold]{len(target_projects)}[/bold] projects.")
    else:
        target_projects = [args.project_id]

    # 2. Batch Execution
    all_reports = []
    if len(target_projects) == 1:
        # Single project: no progress bar, full details
        pid = target_projects[0]
        try:
            result = run_audit_for_project(
                pid, services, args.regions, out_console, args.metrics
            )
            all_reports.append(result)
            if not args.json:
                print_project_detailed(result, out_console)
        except Exception as e:
            log_console.print(
                f"[bold red]Failed to audit project {pid}:[/bold red] {e}"
            )
    else:
        # Multi-project: progress bar, summary output
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=log_console,
        ) as progress:
            task = progress.add_task("Auditing projects...", total=len(target_projects))

            executor = ThreadPoolExecutor(max_workers=args.concurrency)
            futures = {}
            try:
                futures = {
                    executor.submit(
                        run_audit_for_project,
                        pid,
                        services,
                        args.regions,
                        log_console,
                        args.metrics,
                    ): pid
                    for pid in target_projects
                }

                for future in as_completed(futures):
                    project_id = futures[future]
                    try:
                        result = future.result()
                        all_reports.append(result)

                        # Output Logic (Summary for fleet)
                        if not args.json:
                            print_project_summary(result, out_console)

                    except Exception as e:
                        log_console.print(
                            f"[bold red]Failed to audit project {project_id}:"
                            f"[/bold red] {e}"
                        )
                    progress.update(task, advance=1)
            except KeyboardInterrupt:
                log_console.print("\n[bold red]Cancelling audit...[/bold red]")
                executor.shutdown(wait=False, cancel_futures=True)
                sys.exit(130)
            finally:
                # Ensure executor is cleaned up if we exit normally
                executor.shutdown(wait=True)

    # 3. Handle Outputs
    if args.json:
        # Serialize list of reports
        json_output = []
        for report in all_reports:
            entry = {
                "project_id": report["project_id"],
                "scan_time": report["scan_time"].isoformat(),
                "services": {},
            }
            for svc_name, items in report["services"].items():
                if isinstance(items, list):
                    entry["services"][svc_name] = [
                        item.model_dump(mode="json") for item in items
                    ]
                else:
                    # Single object (like GCPIAMReport or GCPVertexReport)
                    entry["services"][svc_name] = items.model_dump(mode="json")
            json_output.append(entry)
        print(json.dumps(json_output, indent=2))

    if args.report or args.html:
        log_console.print("\n[bold]Generating reports...[/bold]")
        try:
            from .reporter import generate_compliance_report

            if args.report:
                generate_compliance_report(
                    all_reports, args.report, output_format="pdf"
                )
            if args.html:
                generate_compliance_report(all_reports, args.html, output_format="html")
            log_console.print("[green]Reports generated successfully.[/green]")
        except Exception as e:
            log_console.print(f"[bold red]Failed to generate reports: {e}[/bold red]")
            # Check for common library missing errors (Pango/Cairo)
            err_msg = str(e).lower()
            if "pango" in err_msg or "cairo" in err_msg or "not found" in err_msg:
                log_console.print(
                    "\n[yellow]Note: PDF rendering requires system libraries.[/yellow]"
                )
                log_console.print(
                    "Try: [bold]sudo apt install libpango-1.0-0 "
                    "libharfbuzz0b libpangoft2-1.0-0[/bold] (Ubuntu/Debian)"
                )
                log_console.print("Or: [bold]brew install pango[/bold] (macOS)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        from rich.console import Console

        console = Console(stderr=True)
        console.print("\n[bold red]Operation cancelled by user.[/bold red]")
        exit(130)
