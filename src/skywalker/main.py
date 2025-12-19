import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import cast

import humanize
from rich.console import Console

# We will import other walkers here as we implement them
from .core import STANDARD_REGIONS, ZONE_SUFFIXES
from .schemas.compute import GCPComputeInstance
from .schemas.gke import GCPCluster
from .schemas.run import GCPCloudRunService
from .schemas.vertex import GCPVertexReport
from .walkers import compute, gke, iam, run, sql, storage, vertex


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Skywalker: GCP Audit & Reporting Tool"
    )
    parser.add_argument("--project-id", help="GCP Project ID to scan", required=True)

    # We removed --zone default. Now users can specify --regions or default to all US.
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

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    parser.add_argument(
        "--report",
        "--pdf",
        dest="report",
        help="Output report to a PDF file (e.g., report.pdf)",
    )

    args = parser.parse_args()

    # If JSON is requested, we silence the console for progress updates
    console = Console(quiet=args.json)
    console.print("[bold green]Skywalker[/bold green] initialized.")

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

    regions = args.regions
    console.print(
        f"Scanning project [bold cyan]{args.project_id}[/bold cyan] "
        f"across [bold]{len(regions)}[/bold] regions..."
    )

    # Data container for JSON output (and PDF input)
    # We store raw Pydantic objects here, and serialize later for JSON.
    report_data = {
        "project_id": args.project_id,
        "scan_time": datetime.utcnow(),
        "services": {},
    }

    # Dispatcher
    try:
        # --- Compute Engine (Zonal) ---
        if "compute" in services:
            console.print("\n[bold]-- Compute Engine --[/bold]")
            total_instances = 0
            compute_results = []

            # Generate target zones from regions
            target_zones = []
            for r in regions:
                for suffix in ZONE_SUFFIXES:
                    target_zones.append(f"{r}-{suffix}")

            # Parallel Scan
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_zone = {
                    executor.submit(scan_compute_zone, args.project_id, zone): zone
                    for zone in target_zones
                }

                # We want to print results in a sorted/deterministic order,
                # but streaming them as they complete feels faster.
                # Let's collect results first, then print.
                results_map = {}
                for future in as_completed(future_to_zone):
                    zone = future_to_zone[future]
                    results_map[zone] = future.result()

            # Process and Print Results
            for zone in sorted(results_map.keys()):
                instances = results_map[zone]
                if instances:
                    total_instances += len(instances)
                    console.print(f"[bold]{zone}[/bold]: Found {len(instances)}")
                    for inst in instances:
                        compute_results.append(inst)
                        gpu_text = f" | {len(inst.gpus)} GPUs" if inst.gpus else ""
                        disk_text = f" | {len(inst.disks)} Disks"
                        ip_text = f" | IP: {inst.internal_ip or 'N/A'}"
                        if inst.external_ip:
                            ip_text += f" ({inst.external_ip})"
                        created_date = inst.creation_timestamp.strftime("%Y-%m-%d")
                        created_text = f" | Created: {created_date}"
                        console.print(
                            f" - [green]{inst.name}[/green] ({inst.machine_type})"
                            f" [{inst.status}]{created_text}{gpu_text}"
                            f"{disk_text}{ip_text}"
                        )

            report_data["services"]["compute"] = compute_results
            if total_instances == 0:
                console.print("No instances found in scanned zones.")

        # --- Cloud Run (Regional) ---
        if "run" in services:
            console.print("\n[bold]-- Cloud Run --[/bold]")
            total_services = 0
            run_results = []

            # Parallel Scan
            with ThreadPoolExecutor(max_workers=len(regions)) as run_executor:
                run_future_to_region = {
                    run_executor.submit(scan_run_region, args.project_id, r): r
                    for r in regions
                }

                run_results_map: dict[str, list[GCPCloudRunService]] = {}
                for run_future in as_completed(run_future_to_region):
                    region = run_future_to_region[run_future]
                    run_results_map[region] = run_future.result()

            # Process and Print Results
            for region in sorted(run_results_map.keys()):
                run_services_list = run_results_map[region]
                if run_services_list:
                    total_services += len(run_services_list)
                    console.print(
                        f"[bold]{region}[/bold]: Found {len(run_services_list)}"
                    )
                    for svc in run_services_list:
                        run_results.append(svc)
                        console.print(
                            f" - [cyan]{svc.name}[/cyan] ({svc.url})\n"
                            f"   Image: {svc.image}\n"
                            f"   Updated: {svc.create_time.strftime('%Y-%m-%d')} "
                            f" | By: {svc.last_modifier}"
                        )

            report_data["services"]["run"] = run_results
            if total_services == 0:
                console.print("No Cloud Run services found in scanned regions.")

        # --- GKE Clusters (Regional) ---
        if "gke" in services:
            console.print("\n[bold]-- GKE Clusters --[/bold]")
            total_clusters = 0
            gke_results = []

            # Parallel Scan across regions
            with ThreadPoolExecutor(max_workers=len(regions)) as gke_executor:
                gke_future_to_location = {
                    gke_executor.submit(scan_gke_location, args.project_id, r): r
                    for r in regions
                }

                gke_results_map: dict[str, list[GCPCluster]] = {}
                for gke_future in as_completed(gke_future_to_location):
                    loc = gke_future_to_location[gke_future]
                    gke_results_map[loc] = gke_future.result()

            # Process and Print Results
            for loc in sorted(gke_results_map.keys()):
                clusters = gke_results_map[loc]
                if clusters:
                    total_clusters += len(clusters)
                    console.print(f"[bold]{loc}[/bold]: Found {len(clusters)}")
                    for cluster in clusters:
                        gke_results.append(cluster)
                        console.print(
                            f" - [cyan]{cluster.name}[/cyan] ({cluster.version}) "
                            f"[{cluster.status}]"
                        )
                        for np in cluster.node_pools:
                            console.print(
                                f"   └ Node Pool: [yellow]{np.name}[/yellow] "
                                f"({np.node_count} nodes, {np.machine_type})"
                            )

            report_data["services"]["gke"] = gke_results
            if total_clusters == 0:
                console.print("No GKE clusters found in scanned regions.")

        # --- IAM (Global) ---
        if "iam" in services:
            console.print("\n[bold]-- IAM & Security --[/bold]")
            iam_report = iam.get_iam_report(project_id=args.project_id)
            report_data["services"]["iam"] = iam_report
            # Print logic already exists... (skipping for brevity)

        # --- Cloud SQL (Global call for project) ---
        if "sql" in services:
            console.print("\n[bold]-- Cloud SQL --[/bold]")
            sql_instances = sql.list_instances(project_id=args.project_id)
            report_data["services"]["sql"] = sql_instances

            console.print(f"Found [bold]{len(sql_instances)}[/bold] instances:")
            for db in sql_instances:
                ip_info = f" | IP: {db.public_ip or db.private_ip or 'None'}"
                console.print(
                    f" - [cyan]{db.name}[/cyan] ({db.database_version} | {db.tier}) "
                    f"[{db.status}]{ip_info} | {db.storage_limit_gb}GB"
                )

        # --- Vertex AI (Regional) ---
        if "vertex" in services:
            console.print("\n[bold]-- Vertex AI --[/bold]")
            vertex_results = GCPVertexReport()

            # Parallel Scan
            with ThreadPoolExecutor(max_workers=len(regions)) as vtx_executor:
                vtx_future_to_loc = {
                    vtx_executor.submit(scan_vertex_location, args.project_id, r): r
                    for r in regions
                }

                for vtx_future in as_completed(vtx_future_to_loc):
                    loc = vtx_future_to_loc[vtx_future]
                    report = vtx_future.result()

                    # Merge results
                    if report.notebooks:
                        console.print(
                            f"[bold]{loc}[/bold]: Found "
                            f"{len(report.notebooks)} Notebooks"
                        )
                        vertex_results.notebooks.extend(report.notebooks)
                        for nb in report.notebooks:
                            console.print(
                                f" - [cyan]{nb.display_name}[/cyan] ({nb.state}) "
                                f"| {nb.creator}"
                            )

                    if report.models:
                        console.print(
                            f"[bold]{loc}[/bold]: Found {len(report.models)} Models"
                        )
                        vertex_results.models.extend(report.models)

                    if report.endpoints:
                        console.print(
                            f"[bold]{loc}[/bold]: Found "
                            f"{len(report.endpoints)} Endpoints"
                        )
                        vertex_results.endpoints.extend(report.endpoints)

            report_data["services"]["vertex"] = vertex_results

            has_vertex = (
                vertex_results.notebooks
                or vertex_results.models
                or vertex_results.endpoints
            )
            if not has_vertex:
                console.print("No Vertex AI resources found in scanned regions.")

        # --- Cloud Storage (Global) ---
        if "storage" in services:
            console.print("\n[bold]-- Cloud Storage --[/bold]")
            buckets = storage.list_buckets(project_id=args.project_id)
            report_data["services"]["storage"] = buckets

            console.print(f"Found [bold]{len(buckets)}[/bold] buckets:")
            for b in buckets:
                pap_status = (
                    f"[green]{b.public_access_prevention}[/green]"
                    if b.public_access_prevention == "enforced"
                    else f"[red]{b.public_access_prevention}[/red]"
                )
                size_str = (
                    humanize.naturalsize(b.size_bytes) if b.size_bytes else "0 Bytes"
                )
                console.print(
                    f" - [cyan]{b.name}[/cyan] ({b.location} | {b.storage_class})"
                    f" | Size: {size_str} | PAP: {pap_status}"
                )

        # ... other services placeholders ...

        # Final JSON Output
        if args.json:
            # We need to manually serialize the objects now
            json_output = {
                "project_id": report_data["project_id"],
                "scan_time": cast(datetime, report_data["scan_time"]).isoformat(),
                "services": {},
            }
            for svc_name, items in report_data["services"].items():
                if isinstance(items, list):
                    json_output["services"][svc_name] = [
                        item.model_dump(mode="json") for item in items
                    ]
                else:
                    # Single object (like GCPIAMReport)
                    json_output["services"][svc_name] = items.model_dump(mode="json")
            print(json.dumps(json_output, indent=2))

        # PDF Output
        if args.report:
            console.print(f"\n[bold]Generating PDF report: {args.report}[/bold]")
            try:
                from .reporter import generate_pdf

                generate_pdf(report_data, args.report)
                console.print("[green]PDF generated successfully.[/green]")
            except Exception as e:
                console.print(f"[bold red]Failed to generate PDF: {e}[/bold red]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
