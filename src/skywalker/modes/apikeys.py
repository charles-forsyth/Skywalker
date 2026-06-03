import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from ..logger import logger
from ..walkers import apikeys, org


def run_api_key_audit(
    args: argparse.Namespace, log_console: Console, out_console: Console
) -> None:
    """
    Executes the deep API Key Audit and Cost Tracking Mode.
    Supports auditing a single project or generating a sortable
    multi-project fleet summary.
    """
    days = getattr(args, "days", 30)
    sort_by = getattr(args, "sort_by", "keys_count")

    # 1. Single Project Scan
    if args.project_id:
        log_console.print(
            f"Auditing API Keys and usages for project "
            f"[bold cyan]{args.project_id}[/bold cyan] over the "
            f"last [bold]{days}[/bold] days..."
        )
        try:
            report = apikeys.get_api_keys_report(args.project_id, days=days)
        except Exception as e:
            logger.error(f"Failed to scan API Keys for {args.project_id}: {e}")
            sys.exit(1)

        if args.json:
            print(report.model_dump_json(indent=2))
            return

        # Render Specific Rich CLI Report
        # Summary Box
        out_console.print()
        out_console.print(
            Panel(
                f"[bold]Project ID:[/bold] {report.project_id}\n"
                f"[bold]Active API Keys:[/bold] {len(report.keys)}\n"
                f"[bold]Total API Requests:[/bold] {report.total_requests:,}\n"
                f"[bold]Total Estimated Cost:[/bold] [bold green]"
                f"${report.total_estimated_cost:,.2f}[/bold green]",
                title="[bold blue]GCP API Key Audit Summary[/bold blue]",
                expand=False,
            )
        )

        # Keys Details Section
        out_console.print(
            "\n[bold underline blue]Audited API Key Credentials[/bold underline blue]"
        )
        if not report.keys:
            out_console.print("No active API keys found in this project.")
        else:
            for k in report.keys:
                status_str = (
                    "[green]✓ Restricted[/green]"
                    if k.is_restricted
                    else "[bold red]⚠ UNRESTRICTED[/bold red]"
                )
                # Calculate key-specific aggregate usages and costs
                cred_ref = f"{k.display_name} ({k.masked_key or k.uid[:8]})"
                key_usages = report.usages.get(cred_ref, [])
                key_requests = sum(u.request_count for u in key_usages)
                key_cost = sum(u.estimated_cost for u in key_usages)

                out_console.print(
                    f"\n• [bold]{k.display_name}[/bold] ({k.masked_key or 'Unknown'})\n"
                    f"  [bold]UID:[/bold] {k.uid}\n"
                    f"  [bold]Created:[/bold] {k.created_at}\n"
                    f"  [bold]Security Status:[/bold] {status_str}\n"
                    f"  [bold]Usage (Last {days} Days):[/bold] "
                    f"{key_requests:,} requests\n"
                    f"  [bold]Est. Cost (Last {days} Days):[/bold] "
                    f"[green]${key_cost:,.2f}[/green]"
                )
                if k.restrictions:
                    out_console.print("  [bold]Restrictions Applied:[/bold]")
                    for rest_type, rest_items in k.restrictions.items():
                        out_console.print(f"    - {rest_type}: {', '.join(rest_items)}")
                elif not k.is_restricted:
                    out_console.print(
                        "  [bold yellow]⚠ Warning: This key has no "
                        "restrictions applied. It is vulnerable to "
                        "abuse and quota theft.[/bold yellow]"
                    )

        # Historical usages section
        out_console.print(
            f"\n[bold underline blue]Historical Usage & "
            f"Estimated Costs (Last {days} Days)[/bold underline blue]"
        )
        if not report.usages:
            out_console.print(
                "No historical request count metrics found for these keys."
            )
        else:
            usage_table = Table(show_header=True, header_style="bold magenta")
            usage_table.add_column("API Key / Credential Reference")
            usage_table.add_column("Google Cloud API Service")
            usage_table.add_column("Request Count", justify="right")
            usage_table.add_column("Est. Cost", justify="right")

            for cred, usages in report.usages.items():
                for u in usages:
                    usage_table.add_row(
                        cred,
                        u.service,
                        f"{u.request_count:,}",
                        f"${u.estimated_cost:,.2f}",
                    )
            out_console.print(usage_table)

    # 2. Multi-project Fleet Scan
    else:
        log_console.print("Discovering active projects for API Key Audit...")
        projects = org.list_all_projects()

        if not projects:
            log_console.print("[bold red]No active projects found.[/bold red]")
            sys.exit(1)

        log_console.print(
            f"Discovered [bold]{len(projects)}[/bold] active "
            f"projects. Running concurrent API Key audit..."
        )

        all_reports: list[Any] = []
        concurrency = getattr(args, "concurrency", 5)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=log_console,
        ) as progress:
            task = progress.add_task("Auditing Projects", total=len(projects))

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = {
                    executor.submit(apikeys.get_api_keys_report, pid, days=days): pid
                    for pid in projects
                }

                for future in as_completed(futures):
                    pid = futures[future]
                    try:
                        report = future.result()
                        all_reports.append(report)
                    except Exception as e:
                        logger.warning(f"Failed to fetch API Key report for {pid}: {e}")
                    progress.update(task, advance=1)

        # Sort reporting results
        # Sort choices: ["project_id", "keys_count", "usage_count", "estimated_cost"]
        if sort_by == "project_id":
            all_reports.sort(key=lambda r: r.project_id)
        elif sort_by == "keys_count":
            all_reports.sort(key=lambda r: len(r.keys), reverse=True)
        elif sort_by == "usage_count":
            all_reports.sort(key=lambda r: r.total_requests, reverse=True)
        elif sort_by == "estimated_cost":
            all_reports.sort(key=lambda r: r.total_estimated_cost, reverse=True)

        if args.json:
            # Output full list as raw json dump
            serialized_reports = [r.model_dump() for r in all_reports]
            print(json.dumps(serialized_reports, indent=2))
            return

        # Render Multi-Project Rich Summary Table
        out_console.print()
        fleet_table = Table(
            title=f"GCP API Key Fleet Audit Summary (Sorted by: {sort_by})",
            show_header=True,
            header_style="bold cyan",
        )
        fleet_table.add_column("Project ID")
        fleet_table.add_column("Key Count", justify="right")
        fleet_table.add_column("Unrestricted Keys", justify="right")
        fleet_table.add_column("Total Requests", justify="right")
        fleet_table.add_column("Est. Cost (Last 30 Days)", justify="right")

        total_keys = 0
        total_unrestricted = 0
        total_requests = 0
        total_cost = 0.0

        for r in all_reports:
            unrestricted_count = sum(1 for k in r.keys if not k.is_restricted)
            unrestricted_str = (
                f"[bold red]{unrestricted_count}[/bold red]"
                if unrestricted_count > 0
                else "0"
            )

            fleet_table.add_row(
                r.project_id,
                str(len(r.keys)),
                unrestricted_str,
                f"{r.total_requests:,}",
                f"${r.total_estimated_cost:,.2f}",
            )

            total_keys += len(r.keys)
            total_unrestricted += unrestricted_count
            total_requests += r.total_requests
            total_cost += r.total_estimated_cost

        # Add totals footer
        fleet_table.add_section()
        unrestricted_footer_str = (
            f"[bold red]{total_unrestricted}[/bold red]"
            if total_unrestricted > 0
            else "0"
        )
        fleet_table.add_row(
            "[bold]TOTALS[/bold]",
            f"[bold]{total_keys}[/bold]",
            unrestricted_footer_str,
            f"[bold]{total_requests:,}[/bold]",
            f"[bold green]${total_cost:,.2f}[/bold green]",
        )

        out_console.print(fleet_table)

        # Render Detailed Fleet Tables for Keys and Usages if keys exist
        if total_keys > 0:
            out_console.print()
            keys_table = Table(
                title=f"All Discovered API Keys Across Fleet ({total_keys} keys found)",
                show_header=True,
                header_style="bold magenta",
            )
            keys_table.add_column("Project ID")
            keys_table.add_column("Key Name (Display Name)")
            keys_table.add_column("Masked Key")
            keys_table.add_column("Security Status")
            keys_table.add_column("Requests", justify="right")
            keys_table.add_column("Est. Cost", justify="right")
            keys_table.add_column("Created At")

            for r in all_reports:
                for k in r.keys:
                    status_str = (
                        "[green]✓ Restricted[/green]"
                        if k.is_restricted
                        else "[bold red]⚠ UNRESTRICTED[/bold red]"
                    )
                    # Calculate aggregate requests and estimated cost for this key
                    cred_ref = f"{k.display_name} ({k.masked_key or k.uid[:8]})"
                    key_usages = r.usages.get(cred_ref, [])
                    key_requests = sum(u.request_count for u in key_usages)
                    key_cost = sum(u.estimated_cost for u in key_usages)

                    keys_table.add_row(
                        r.project_id,
                        k.display_name or "Unnamed Key",
                        k.masked_key or "Unknown",
                        status_str,
                        f"{key_requests:,}",
                        f"${key_cost:,.2f}",
                        k.created_at or "Unknown",
                    )
            out_console.print(keys_table)

        # Check if there are any historical usages to display
        has_usages = any(len(r.usages) > 0 for r in all_reports)
        if has_usages:
            out_console.print()
            usage_table = Table(
                title=f"API Key Usage & Estimated Cost Breakdown (Last {days} Days)",
                show_header=True,
                header_style="bold magenta",
            )
            usage_table.add_column("Project ID")
            usage_table.add_column("API Key / Credential Reference")
            usage_table.add_column("Google Cloud API Service")
            usage_table.add_column("Request Count", justify="right")
            usage_table.add_column("Est. Cost", justify="right")

            for r in all_reports:
                for cred_ref, records in r.usages.items():
                    for u in records:
                        usage_table.add_row(
                            r.project_id,
                            cred_ref,
                            u.service,
                            f"{u.request_count:,}",
                            f"${u.estimated_cost:,.2f}",
                        )
            out_console.print(usage_table)
