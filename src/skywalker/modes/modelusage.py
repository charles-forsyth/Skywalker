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
from ..walkers import modelusage, org


def run_model_audit(
    args: argparse.Namespace, log_console: Console, out_console: Console
) -> None:
    """
    Executes the Model Usage and Cost Tracking mode.
    Audits a single project or provides a sortable multi-project fleet summary.
    """
    days = getattr(args, "days", 30)
    sort_by = getattr(args, "sort_by", "estimated_cost")
    if sort_by not in ["project_id", "usage_count", "estimated_cost"]:
        sort_by = "estimated_cost"

    # 1. Single Project Scan
    if args.project_id:
        log_console.print(
            f"Auditing AI/Publisher Model usage for project "
            f"[bold cyan]{args.project_id}[/bold cyan] over the "
            f"last [bold]{days}[/bold] days..."
        )
        try:
            report = modelusage.get_model_usage_report(args.project_id, days=days)
        except Exception as e:
            logger.error(f"Failed to scan models for {args.project_id}: {e}")
            sys.exit(1)

        if args.json:
            print(report.model_dump_json(indent=2))
            return

        # Render Rich Single-Project Report
        out_console.print()
        out_console.print(
            Panel(
                f"[bold]Project ID:[/bold] {report.project_id}\n"
                f"[bold]Active Models:[/bold] {len(report.usages)}\n"
                f"[bold]Total Requests:[/bold] {report.total_requests:,}\n"
                f"[bold]Total Input Tokens:[/bold] {report.total_input_tokens:,}\n"
                f"[bold]Total Output Tokens:[/bold] {report.total_output_tokens:,}\n"
                f"[bold]Total Estimated Cost:[/bold] [bold green]"
                f"${report.total_estimated_cost:,.2f}[/bold green]",
                title="[bold blue]GCP Model Usage & Cost Summary[/bold blue]",
                expand=False,
            )
        )

        out_console.print(
            f"\n[bold underline blue]Granular Model Usages & "
            f"Estimated Costs (Last {days} Days)[/bold underline blue]"
        )
        if not report.usages:
            out_console.print(
                "No active model invocation or token usage metrics found."
            )
        else:
            model_table = Table(show_header=True, header_style="bold magenta")
            model_table.add_column("Model ID (User ID)")
            model_table.add_column("Publisher")
            model_table.add_column("Request Count", justify="right")
            model_table.add_column("Input Tokens", justify="right")
            model_table.add_column("Output Tokens", justify="right")
            model_table.add_column("Est. Cost", justify="right")

            for u in report.usages:
                model_table.add_row(
                    u.model_id,
                    u.publisher,
                    f"{u.request_count:,}",
                    f"{u.input_tokens:,}",
                    f"{u.output_tokens:,}",
                    f"${u.estimated_cost:,.2f}",
                )
            out_console.print(model_table)

    # 2. Multi-project Fleet Scan
    else:
        log_console.print("Discovering active projects for Model Audit...")
        projects = org.list_all_projects()

        if not projects:
            log_console.print("[bold red]No active projects found.[/bold red]")
            sys.exit(1)

        log_console.print(
            f"Discovered [bold]{len(projects)}[/bold] active "
            f"projects. Running concurrent Model audit..."
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
                    executor.submit(
                        modelusage.get_model_usage_report, pid, days=days
                    ): pid
                    for pid in projects
                }

                for future in as_completed(futures):
                    pid = futures[future]
                    try:
                        report = future.result()
                        all_reports.append(report)
                    except Exception as e:
                        logger.warning(f"Failed to fetch model report for {pid}: {e}")
                    progress.update(task, advance=1)

        # Sort reporting results
        if sort_by == "project_id":
            all_reports.sort(key=lambda r: r.project_id)
        elif sort_by == "usage_count":
            all_reports.sort(key=lambda r: r.total_requests, reverse=True)
        elif sort_by == "estimated_cost":
            all_reports.sort(key=lambda r: r.total_estimated_cost, reverse=True)

        if args.json:
            serialized_reports = [r.model_dump() for r in all_reports]
            print(json.dumps(serialized_reports, indent=2))
            return

        # Render Multi-Project Rich Summary Table
        out_console.print()
        fleet_table = Table(
            title=f"GCP Model Usage Fleet Audit Summary (Sorted by: {sort_by})",
            show_header=True,
            header_style="bold cyan",
        )
        fleet_table.add_column("Project ID")
        fleet_table.add_column("Models Used", justify="right")
        fleet_table.add_column("Total Requests", justify="right")
        fleet_table.add_column("Total Input Tokens", justify="right")
        fleet_table.add_column("Total Output Tokens", justify="right")
        fleet_table.add_column("Est. Cost (Last 30 Days)", justify="right")

        total_models = 0
        total_requests = 0
        total_input = 0
        total_output = 0
        total_cost = 0.0

        for r in all_reports:
            fleet_table.add_row(
                r.project_id,
                str(len(r.usages)),
                f"{r.total_requests:,}",
                f"{r.total_input_tokens:,}",
                f"{r.total_output_tokens:,}",
                f"${r.total_estimated_cost:,.2f}",
            )

            total_models += len(r.usages)
            total_requests += r.total_requests
            total_input += r.total_input_tokens
            total_output += r.total_output_tokens
            total_cost += r.total_estimated_cost

        # Add totals footer
        fleet_table.add_section()
        fleet_table.add_row(
            "[bold]TOTALS[/bold]",
            f"[bold]{total_models}[/bold]",
            f"[bold]{total_requests:,}[/bold]",
            f"[bold]{total_input:,}[/bold]",
            f"[bold]{total_output:,}[/bold]",
            f"[bold green]${total_cost:,.2f}[/bold green]",
        )

        out_console.print(fleet_table)

        # Render Detailed Fleet Tables for individual models if usage exists
        if total_models > 0:
            out_console.print()
            detail_table = Table(
                title=(
                    f"All Discovered Models Across Fleet ({total_models} models found)"
                ),
                show_header=True,
                header_style="bold magenta",
            )
            detail_table.add_column("Project ID")
            detail_table.add_column("Model ID (User ID)")
            detail_table.add_column("Publisher")
            detail_table.add_column("Request Count", justify="right")
            detail_table.add_column("Input Tokens", justify="right")
            detail_table.add_column("Output Tokens", justify="right")
            detail_table.add_column("Est. Cost", justify="right")

            for r in all_reports:
                for u in r.usages:
                    detail_table.add_row(
                        r.project_id,
                        u.model_id,
                        u.publisher,
                        f"{u.request_count:,}",
                        f"{u.input_tokens:,}",
                        f"{u.output_tokens:,}",
                        f"${u.estimated_cost:,.2f}",
                    )
            out_console.print(detail_table)
