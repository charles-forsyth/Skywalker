import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import jinja2
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..clients import get_bigquery_client
from ..logger import logger


def is_valid_bq_table(name: str) -> bool:
    """
    Validates that a string has a valid BigQuery table format.

    Format: project_id.dataset_id.table_id to prevent any potential SQL injection.
    """
    pattern = r"^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+){1,2}$"
    return bool(re.match(pattern, name))


def run_billing_report(
    args: argparse.Namespace, log_console: Console, out_console: Console
) -> None:
    """
    Queries BigQuery Billing Export to provide a summary of GCP costs and credits.
    """
    days = getattr(args, "days", 30)
    scoping_project = args.scoping_project or "ucr-research-computing"
    billing_account_id = (
        getattr(args, "billing_account", None) or "01B8C7-D13B5E-17457B"
    )
    billing_account_clean = billing_account_id.replace("-", "_")

    if getattr(args, "billing_table", None):
        billing_table = args.billing_table
    else:
        billing_table = (
            f"{scoping_project}.gcp_billing."
            f"gcp_billing_export_v1_{billing_account_clean}"
        )

    # Validate table identifier format
    if not is_valid_bq_table(billing_table):
        log_console.print(
            "[bold red]Error:[/bold red] "
            f"Invalid BigQuery table name format: '{billing_table}'"
        )
        sys.exit(1)

    log_console.print(
        "Querying Billing Export for account "
        f"[bold cyan]{billing_account_id}[/bold cyan] "
        f"from [bold]{billing_table}[/bold] "
        f"(Last [bold]{days}[/bold] days)..."
    )

    # Construct and run the query
    if args.project_id:
        query = f"""
            SELECT
              COALESCE(service.description, 'Unknown Service') AS service_description,
              COALESCE(sku.description, 'Unknown SKU') AS sku_description,
              SUM(cost) AS raw_cost,
              SUM(COALESCE((
                SELECT SUM(c.amount) FROM UNNEST(credits) c
              ), 0.0)) AS credits,
              SUM(cost) + SUM(COALESCE((
                SELECT SUM(c.amount) FROM UNNEST(credits) c
              ), 0.0)) AS net_cost
            FROM
              `{billing_table}`
            WHERE
              project.id = @project_id
              AND usage_start_time >= TIMESTAMP_SUB(
                CURRENT_TIMESTAMP(), INTERVAL @days DAY
              )
            GROUP BY
              service_description,
              sku_description
            ORDER BY
              net_cost DESC
        """
        query_params = [
            bigquery_param("project_id", "STRING", args.project_id),
            bigquery_param("days", "INT64", days),
        ]
    else:
        query = f"""
            SELECT
              COALESCE(project.id, '[No Project / Tax / Support]') AS project_id,
              COALESCE(project.name, '[No Project / Tax / Support]') AS project_name,
              SUM(cost) AS raw_cost,
              SUM(COALESCE((
                SELECT SUM(c.amount) FROM UNNEST(credits) c
              ), 0.0)) AS credits,
              SUM(cost) + SUM(COALESCE((
                SELECT SUM(c.amount) FROM UNNEST(credits) c
              ), 0.0)) AS net_cost
            FROM
              `{billing_table}`
            WHERE
              usage_start_time >= TIMESTAMP_SUB(
                CURRENT_TIMESTAMP(), INTERVAL @days DAY
              )
            GROUP BY
              project_id,
              project_name
            ORDER BY
              net_cost DESC
        """
        query_params = [
            bigquery_param("days", "INT64", days),
        ]

    try:
        from google.cloud import bigquery

        client = get_bigquery_client(project=scoping_project)
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        query_job = client.query(query, job_config=job_config)
        results = query_job.result()
    except Exception as e:
        logger.error(f"BigQuery Query Failed: {e}")
        log_console.print(
            "[bold red]Error:[/bold red] BigQuery Query Failed. "
            "Make sure you have authorized credentials and proper dataset permissions. "
            f"Details: {e}"
        )
        sys.exit(1)

    # Process results
    rows: list[dict[str, Any]] = []
    total_raw_cost = 0.0
    total_credits = 0.0
    total_net_cost = 0.0

    for r in results:
        row_dict: dict[str, Any] = {
            "raw_cost": float(r.raw_cost or 0.0),
            "credits": float(r.credits or 0.0),
            "net_cost": float(r.net_cost or 0.0),
        }
        if args.project_id:
            row_dict["service_description"] = str(r.service_description)
            row_dict["sku_description"] = str(r.sku_description)
        else:
            row_dict["project_id"] = str(r.project_id)
            row_dict["project_name"] = str(r.project_name)

        rows.append(row_dict)
        total_raw_cost += row_dict["raw_cost"]
        total_credits += row_dict["credits"]
        total_net_cost += row_dict["net_cost"]

    totals = {
        "total_raw_cost": total_raw_cost,
        "total_credits": total_credits,
        "total_net_cost": total_net_cost,
    }

    scan_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Outputs
    # 1. JSON Output
    if getattr(args, "json", False):
        output_data = {
            "report_type": "project" if args.project_id else "fleet",
            "project_id": args.project_id,
            "days": days,
            "billing_account": billing_account_id,
            "billing_table": billing_table,
            "scan_time": scan_time_str,
            "totals": totals,
            "rows": rows,
        }
        print(json.dumps(output_data, indent=2))
        return

    # 2. CSV Output
    if getattr(args, "csv", None):
        csv_path = Path(args.csv)
        try:
            with csv_path.open(mode="w", newline="", encoding="utf-8") as f:
                if args.project_id:
                    fieldnames = [
                        "service_description",
                        "sku_description",
                        "raw_cost",
                        "credits",
                        "net_cost",
                    ]
                else:
                    fieldnames = [
                        "project_id",
                        "project_name",
                        "raw_cost",
                        "credits",
                        "net_cost",
                    ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: row[k] for k in fieldnames})
            log_console.print(f"[green]✓ Saved CSV report to {csv_path}[/green]")
        except Exception as e:
            logger.error(f"Failed to write CSV report: {e}")
            log_console.print(
                f"[bold red]Error:[/bold red] "
                f"Failed to write CSV report to {csv_path}: {e}"
            )

    # 3. HTML Output
    if getattr(args, "html", None):
        html_path = Path(args.html)
        try:
            template_dir = Path(__file__).parent.parent / "templates"
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(template_dir)),
                autoescape=jinja2.select_autoescape(["html", "xml"]),
            )
            template = env.get_template("billing_report.html")
            html_content = template.render(
                report_type="project" if args.project_id else "fleet",
                project_id=args.project_id,
                days=days,
                billing_account=billing_account_id,
                billing_table=billing_table,
                scan_time=scan_time_str,
                totals=totals,
                rows=rows,
            )
            html_path.write_text(html_content, encoding="utf-8")
            log_console.print(f"[green]✓ Saved HTML report to {html_path}[/green]")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")
            log_console.print(
                f"[bold red]Error:[/bold red] "
                f"Failed to write HTML report to {html_path}: {e}"
            )

    # 4. Standard Rich Console Output
    out_console.print()
    out_console.print(
        Panel(
            f"[bold]Billing Account:[/bold] {billing_account_id}\n"
            f"[bold]Query Table:[/bold] {billing_table}\n"
            f"[bold]Time Window:[/bold] Last {days} Days\n"
            f"[bold]Total Raw Cost:[/bold] ${totals['total_raw_cost']:,.2f}\n"
            f"[bold]Total Credits Applied:[/bold] "
            f"[green]${totals['total_credits']:,.2f}[/green]\n"
            f"[bold]Net Cost (Invoiced):[/bold] "
            f"[bold rose]${totals['total_net_cost']:,.2f}[/bold rose]",
            title="[bold blue]FinOps Billing Summary[/bold blue]",
            expand=False,
        )
    )

    out_console.print()
    if args.project_id:
        title = f"Project Cost Distribution: {args.project_id}"
    else:
        title = "Fleet-wide Project Cost Overview"

    table = Table(show_header=True, header_style="bold cyan", title=title)
    if args.project_id:
        table.add_column("Service Description")
        table.add_column("SKU Description")
    else:
        table.add_column("Project ID")
        table.add_column("Project Name")

    table.add_column("Raw Cost", justify="right", style="magenta")
    table.add_column("Credits", justify="right", style="green")
    table.add_column("Net Cost", justify="right", style="bold blue")

    for row in rows:
        if args.project_id:
            col1 = row["service_description"]
            col2 = row["sku_description"]
        else:
            col1 = row["project_id"]
            col2 = row["project_name"]

        table.add_row(
            col1,
            col2,
            f"${row['raw_cost']:,.2f}",
            f"${row['credits']:,.2f}",
            f"${row['net_cost']:,.2f}",
        )

    out_console.print(table)


def bigquery_param(name: str, type_: str, value: Any) -> Any:
    """
    Helper to safely instantiate a BigQuery ScalarQueryParameter.

    Used to avoid NameError if import-not-found triggers on import.
    """
    from google.cloud import bigquery

    return bigquery.ScalarQueryParameter(name, type_, value)
