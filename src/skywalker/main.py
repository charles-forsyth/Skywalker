import argparse
import sys

import humanize
from rich.console import Console

# We will import other walkers here as we implement them
from .core import STANDARD_REGIONS, ZONE_SUFFIXES
from .walkers import compute, run, storage


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
        default=["compute"],
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
        help="List of services to audit (default: compute)",
    )

    args = parser.parse_args()

    console = Console()
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

    # Dispatcher
    try:
        # --- Compute Engine (Zonal) ---
        if "compute" in services:
            console.print("\n[bold]-- Compute Engine --[/bold]")
            total_instances = 0

            # Generate target zones from regions
            target_zones = []
            for r in regions:
                for suffix in ZONE_SUFFIXES:
                    target_zones.append(f"{r}-{suffix}")

            # Scan zones
            # TODO: Parallelize this loop for speed
            for zone in target_zones:
                try:
                    instances = compute.list_instances(
                        project_id=args.project_id, zone=zone
                    )
                    if instances:
                        total_instances += len(instances)
                        console.print(f"[bold]{zone}[/bold]: Found {len(instances)}")
                        for inst in instances:
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
                except Exception:
                    # Ignore zones that don't exist or errors
                    # (for now, to keep scanning)
                    pass

            if total_instances == 0:
                console.print("No instances found in scanned zones.")

        # --- Cloud Run (Regional) ---
        if "run" in services:
            console.print("\n[bold]-- Cloud Run --[/bold]")
            total_services = 0

            for region in regions:
                try:
                    run_services = run.list_services(
                        project_id=args.project_id, region=region
                    )
                    if run_services:
                        total_services += len(run_services)
                        console.print(
                            f"[bold]{region}[/bold]: Found {len(run_services)}"
                        )
                        for svc in run_services:
                            console.print(
                                f" - [cyan]{svc.name}[/cyan] ({svc.url})\n"
                                f"   Image: {svc.image}\n"
                                f"   Updated: {svc.create_time.strftime('%Y-%m-%d')} "
                                f"| By: {svc.last_modifier}"
                            )
                except Exception:
                    pass

            if total_services == 0:
                console.print("No Cloud Run services found in scanned regions.")

        # --- Cloud Storage (Global) ---
        if "storage" in services:
            console.print("\n[bold]-- Cloud Storage --[/bold]")
            buckets = storage.list_buckets(project_id=args.project_id)
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

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
