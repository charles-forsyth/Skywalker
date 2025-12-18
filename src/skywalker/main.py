import argparse
import sys

import humanize
from rich.console import Console

# We will import other walkers here as we implement them
from .walkers import compute, storage


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Skywalker: GCP Audit & Reporting Tool"
    )
    parser.add_argument("--project-id", help="GCP Project ID to scan", required=True)
    parser.add_argument("--zone", help="GCP Zone to scan", default="us-west1-b")
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

    console.print(
        f"Scanning project [bold cyan]{args.project_id}[/bold cyan] "
        f"in zone [bold cyan]{args.zone}[/bold cyan]..."
    )

    # Dispatcher
    try:
        if "compute" in services:
            console.print("\n[bold]-- Compute Engine --[/bold]")
            instances = compute.list_instances(
                project_id=args.project_id, zone=args.zone
            )
            console.print(f"Found [bold]{len(instances)}[/bold] instances:")
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
                    f" [{inst.status}]{created_text}{gpu_text}{disk_text}{ip_text}"
                )

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
