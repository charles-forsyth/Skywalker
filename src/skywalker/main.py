import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, cast

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .core import STANDARD_REGIONS, ZONE_SUFFIXES
from .schemas.compute import GCPComputeInstance
from .schemas.gke import GCPCluster
from .schemas.run import GCPCloudRunService
from .schemas.vertex import GCPVertexReport
from .walkers import compute, gke, iam, network, org, run, sql, storage, vertex


def scan_compute_zone(project_id: str, zone: str) -> list[GCPComputeInstance]:
    try:
        return cast(
            list[GCPComputeInstance],
            compute.list_instances(project_id=project_id, zone=zone),
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
    project_id: str, services: list[str], regions: list[str], console: Console
) -> dict[str, Any]:
    """
    Executes all requested walkers for a single project and returns the combined data.
    """
    report_data: dict[str, Any] = {
        "project_id": project_id,
        "scan_time": datetime.now(timezone.utc),
        "services": {},
    }

    # --- Compute Engine (Zonal) ---
    if "compute" in services:
        compute_results = []
        target_zones = [f"{r}-{s}" for r in regions for s in ZONE_SUFFIXES]
        with ThreadPoolExecutor(max_workers=10) as compute_executor:
            future_to_zone = {
                compute_executor.submit(scan_compute_zone, project_id, z): z
                for z in target_zones
            }
            for compute_future in as_completed(future_to_zone):
                compute_results.extend(compute_future.result())
        report_data["services"]["compute"] = compute_results

    # --- Cloud Run (Regional) ---
    if "run" in services:
        run_results = []
        with ThreadPoolExecutor(max_workers=len(regions)) as run_executor:
            run_futures = [
                run_executor.submit(scan_run_region, project_id, r) for r in regions
            ]
            for run_future in as_completed(run_futures):
                run_results.extend(run_future.result())
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
        try:
            report_data["services"]["iam"] = iam.get_iam_report(project_id)
        except Exception as e:
            console.print(
                f"[yellow]Warning: IAM scan failed for {project_id}: {e}[/yellow]"
            )

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
        console.print(
            f" - Compute Engine: [bold]{len(services['compute'])}[/bold] instances"
        )
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Skywalker: GCP Audit & Reporting Tool"
    )
    group = parser.add_mutually_exclusive_group(required=True)
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
    parser.add_argument("--report", "--pdf", dest="report", help="Output report to PDF")
    parser.add_argument("--html", help="Output report to an HTML file")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of projects to scan in parallel (default: 5)",
    )

    args = parser.parse_args()

    # Use stderr for logs/progress if stdout is piped for JSON
    log_console = Console(stderr=True, quiet=args.json)
    out_console = Console(quiet=args.json)

    log_console.print("[bold green]Skywalker[/bold green] Fleet Commander initialized.")

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
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=log_console,
    ) as progress:
        task = progress.add_task("Auditing projects...", total=len(target_projects))

        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            futures = {
                executor.submit(
                    run_audit_for_project, pid, services, args.regions, log_console
                ): pid
                for pid in target_projects
            }

            for future in as_completed(futures):
                project_id = futures[future]
                try:
                    result = future.result()
                    all_reports.append(result)
                    if not args.json:
                        print_project_summary(result, out_console)
                except Exception as e:
                    log_console.print(
                        f"[bold red]Failed to audit project {project_id}:"
                        f"[/bold red] {e}"
                    )
                progress.update(task, advance=1)

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
                    entry["services"][svc_name] = items.model_dump(mode="json")
            json_output.append(entry)
        print(json.dumps(json_output, indent=2))

    if args.report or args.html:
        log_console.print("\n[bold]Generating reports...[/bold]")
        try:
            from .reporter import generate_fleet_report

            if args.report:
                generate_fleet_report(all_reports, args.report, output_format="pdf")
            if args.html:
                generate_fleet_report(all_reports, args.html, output_format="html")
            log_console.print("[green]Reports generated successfully.[/green]")
        except Exception as e:
            log_console.print(f"[bold red]Failed to generate reports: {e}[/bold red]")


if __name__ == "__main__":
    main()
