import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import jinja2
import pandas as pd
from rich.console import Console
from rich.table import Table

from ..walkers import asset, monitoring

DEFAULT_SCOPING_PROJECT = "ucr-research-computing"


def run_fleet_monitor(
    args: argparse.Namespace, log_console: Console, out_console: Console
) -> None:
    """
    Executes the Fleet Performance Monitoring logic.
    """
    scoping_proj = args.scoping_project or DEFAULT_SCOPING_PROJECT
    log_console.print(
        f"Entering [bold cyan]Fleet Performance Mode[/bold cyan] "
        f"via scope: {scoping_proj}"
    )

    try:
        # 1. Fetch Metrics
        metrics_data = monitoring.fetch_fleet_metrics(scoping_proj)

        # 2. Identify Projects to Scan
        projects_to_scan = {
            m.get("project_id") for m in metrics_data if m.get("project_id")
        }

        log_console.print(
            f"Fetching inventory for {len(projects_to_scan)} active projects..."
        )

        assets = {}
        # If org-id provided, try huge scan. Else iterate projects.
        if args.org_id:
            try:
                assets = asset.search_all_instances(f"organizations/{args.org_id}")
            except Exception:
                log_console.print(
                    "[yellow]Org-level search failed. "
                    "Falling back to project iteration.[/yellow]"
                )
                # Fallback logic below...

        if not assets:
            with ThreadPoolExecutor(max_workers=20) as executor:
                # Submit asset search for each project
                futures = {
                    executor.submit(asset.search_all_instances, f"projects/{pid}"): pid
                    for pid in projects_to_scan
                }

                for future in as_completed(futures):
                    try:
                        project_assets = future.result()
                        assets.update(project_assets)
                    except Exception:
                        pass  # Ignore failures for individual projects

        # 3. Enrich Data
        enriched_data = []
        for m in metrics_data:
            iid = str(m.get("instance_id", ""))
            if iid and iid in assets:
                m["instance_name"] = assets[iid]["name"]
                m["machine_type"] = assets[iid]["machine_type"]
            else:
                m["instance_name"] = "unknown"
                m["machine_type"] = "unknown"
            enriched_data.append(m)

        df = pd.DataFrame(enriched_data)

        if df.empty:
            log_console.print("[yellow]No metrics found in scope.[/yellow]")
            return

        # Console Output (Rich Table)
        if not args.json:
            table = Table(title="Fleet Top Consumers")
            table.add_column("Project", style="cyan")
            table.add_column("Name", style="bold green")
            table.add_column("Type", style="dim")
            table.add_column("CPU %", justify="right")
            table.add_column("Mem %", justify="right")
            table.add_column("GPU Util %", justify="right")

            # Sort by CPU desc (treat NaN as 0 for sorting)
            top_cpu = df.sort_values(
                by="cpu_percent", ascending=False, na_position="last"
            ).head(args.limit)

            for _, row in top_cpu.iterrows():
                # CPU
                if pd.notna(row.get("cpu_percent")):
                    cpu_val = row["cpu_percent"]
                    cpu_style = "red" if cpu_val > 90 else "white"
                    cpu_str = f"[{cpu_style}]{cpu_val:.1f}%[/{cpu_style}]"
                else:
                    cpu_str = "[dim]N/A[/dim]"

                # Memory
                if pd.notna(row.get("memory_percent")):
                    mem_val = row["memory_percent"]
                    mem_str = f"{mem_val:.1f}%"
                else:
                    mem_str = "[dim]N/A[/dim]"

                # GPU
                if pd.notna(row.get("gpu_utilization")):
                    gpu_val = row["gpu_utilization"]
                    gpu_style = "magenta" if gpu_val > 0 else "dim"
                    gpu_str = f"[{gpu_style}]{gpu_val:.1f}%[/{gpu_style}]"
                else:
                    gpu_str = "[dim]-[/dim]"

                table.add_row(
                    str(row["project_id"]),
                    str(row["instance_name"]),
                    str(row["machine_type"]),
                    cpu_str,
                    mem_str,
                    gpu_str,
                )
            out_console.print(table)
            out_console.print(f"\nTotal Instances Monitored: [bold]{len(df)}[/bold]")

        # JSON Output
        if args.json:
            print(df.to_json(orient="records"))

        # CSV Output
        if args.csv:
            df.to_csv(args.csv, index=False)
            log_console.print(f"Data saved to [bold]{args.csv}[/bold]")

        # HTML Report (if requested)
        if args.html:
            template_dir = Path(__file__).parent.parent / "templates"
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(str(template_dir)),
                autoescape=jinja2.select_autoescape(["html", "xml"]),
            )
            template = env.get_template("fleet_performance.html")
            html_content = template.render(
                data=enriched_data,
                scoping_project=scoping_proj,
                scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )

            with Path(args.html).open("w") as f:
                f.write(html_content)
            log_console.print(f"Report saved to [bold]{args.html}[/bold]")

    except Exception as e:
        log_console.print(f"[bold red]Fleet Audit Failed:[/bold red] {e}")
