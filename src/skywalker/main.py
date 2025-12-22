import argparse
from importlib.metadata import version

from rich.console import Console

from .core import STANDARD_REGIONS
from .logger import logger
from .modes import audit, monitor


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

  # Enter Fleet Performance Mode (monitors all projects in Ursa Major scope)
  skywalker --monitor

  # Monitor and save to HTML dashboard
  skywalker --monitor --html fleet_dashboard.html
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
    group.add_argument(
        "--monitor",
        action="store_true",
        help="Enter Fleet Performance Monitoring Mode",
    )

    parser.add_argument(
        "--scoping-project",
        help="Override default Scoping Project (ucr-research-computing)",
    )
    parser.add_argument(
        "--org-id",
        help="Organization ID for Asset Inventory search (e.g. 123456789)",
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
            "filestore",
            "iam",
            "run",
            "network",
            "all",
        ],
        help="List of services to audit (default: all)",
    )

    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--csv", help="Output fleet performance data to CSV file")
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
        "--limit",
        type=int,
        default=20,
        help="Number of rows to display in terminal table (default: 20)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Legacy flag (caching is now disabled by default)",
    )

    args = parser.parse_args()

    # Must validate required args manually since group is now optional for --version
    if not any([args.project_id, args.all_projects, args.monitor]):
        parser.error(
            "one of the arguments --project-id --all-projects --monitor is required"
        )

    # Use stderr for logs/progress if stdout is piped for JSON
    log_console = Console(stderr=True, quiet=args.json)
    out_console = Console(quiet=args.json)

    log_console.print(
        "[bold green]Skywalker[/bold green] Ursa Major Auditor initialized."
    )

    # Dispatch to Modes
    if args.monitor:
        try:
            monitor.run_fleet_monitor(args, log_console, out_console)
        except Exception as e:
            logger.error(f"Fleet Monitor Failed: {e}")
            exit(1)
    else:
        # Audit Mode
        try:
            audit.run_fleet_audit(args, log_console, out_console)
        except Exception as e:
            logger.error(f"Audit Failed: {e}")
            exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        from rich.console import Console

        console = Console(stderr=True)
        console.print("\n[bold red]Operation cancelled by user.[/bold red]")
        exit(130)
