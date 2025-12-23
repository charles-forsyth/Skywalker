import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from rich.console import Console
from rich.table import Table

from ..clients import get_disks_client
from ..logger import logger
from ..walkers import monitoring, network, storage


@dataclass
class ZombieResource:
    resource_type: str
    project_id: str
    name: str
    details: str
    monthly_cost_est: float = 0.0
    reason: str = ""


class ZombieHunter:
    def __init__(self, console: Console):
        self.console = console
        self.zombies: list[ZombieResource] = []

    def hunt_disks(self, project_id: str) -> None:
        """Finds orphaned disks (not attached to any user)."""
        try:
            client = get_disks_client()
            for _zone, disks in client.aggregated_list(project=project_id):
                if not disks.disks:
                    continue
                for disk in disks.disks:
                    if not disk.users:
                        # Orphan!
                        size = disk.size_gb
                        disk_type = disk.type_.split("/")[-1]  # pd-standard, pd-ssd

                        # Rough cost: Standard $0.04, SSD $0.17
                        cost = size * 0.04
                        if "ssd" in disk_type:
                            cost = size * 0.17
                        elif "balanced" in disk_type:
                            cost = size * 0.10

                        self.zombies.append(
                            ZombieResource(
                                resource_type="Disk",
                                project_id=project_id,
                                name=disk.name,
                                details=f"{size}GB ({disk_type})",
                                monthly_cost_est=cost,
                                reason="Orphaned (No VM attached)",
                            )
                        )
        except Exception as e:
            logger.debug(f"Failed to hunt disks in {project_id}: {e}")

    def hunt_ips(self, project_id: str) -> None:
        """Finds unused static IPs."""
        try:
            report = network.get_network_report(project_id)
            for addr in report.addresses:
                # Only care about EXTERNAL IPs costing money
                if (
                    addr.status == "RESERVED"
                    and not addr.user
                    and addr.address_type == "EXTERNAL"
                ):
                    self.zombies.append(
                        ZombieResource(
                            resource_type="Static IP",
                            project_id=project_id,
                            name=addr.name,
                            details=addr.address,
                            monthly_cost_est=7.30,
                            reason="Reserved External IP not in use",
                        )
                    )
        except Exception as e:
            logger.debug(f"Failed to hunt IPs in {project_id}: {e}")

    def hunt_buckets(self, project_id: str) -> None:
        """Finds inactive buckets (Zero IO for 30 days)."""
        try:
            buckets = storage.list_buckets(project_id)
            if not buckets:
                return

            # Fetch activity
            activity = monitoring.fetch_inactive_resources(
                project_id,
                metric_type="storage.googleapis.com/network/sent_bytes_count",
                resource_type="gcs_bucket",
                days=30,
                group_by=["resource.label.bucket_name"],
            )

            for b in buckets:
                # If total sent bytes is 0 (or very low < 1MB), call it a zombie
                sent = activity.get(b.name, 0)
                if sent < 1_000_000:  # Less than 1MB in 30 days
                    size_gb = b.size_bytes / (1024**3)
                    if size_gb < 1:  # Ignore tiny buckets
                        continue

                    cost = size_gb * 0.02

                    self.zombies.append(
                        ZombieResource(
                            resource_type="Bucket",
                            project_id=project_id,
                            name=b.name,
                            details=f"Size: {int(size_gb)} GB",
                            monthly_cost_est=cost,
                            reason="Inactive (Zero egress 30d)",
                        )
                    )
        except Exception as e:
            logger.debug(f"Failed to hunt buckets in {project_id}: {e}")


def run_zombie_hunt(args: Any, log_console: Console, out_console: Console) -> None:
    hunter = ZombieHunter(log_console)

    # 1. Scope
    projects = []
    if args.all_projects:
        from ..walkers import org

        projects = org.list_all_projects()
    else:
        projects = [args.project_id]

    log_console.print(f"Hunting Zombies across {len(projects)} projects...")

    # 2. Parallel Hunt
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for pid in projects:
            futures.append(executor.submit(hunter.hunt_disks, pid))
            futures.append(executor.submit(hunter.hunt_ips, pid))
            futures.append(executor.submit(hunter.hunt_buckets, pid))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.debug(f"Hunter task failed: {e}")

    # 3. Report
    if not hunter.zombies:
        if not args.json:
            out_console.print("[green]No Zombies Found! Fleet is clean.[/green]")
        else:
            print("[]")
        return

    # Sort by cost desc
    hunter.zombies.sort(key=lambda z: z.monthly_cost_est, reverse=True)
    total_waste = sum(z.monthly_cost_est for z in hunter.zombies)

    # Prepare data for non-terminal outputs
    zombie_dicts = [asdict(z) for z in hunter.zombies]
    df = pd.DataFrame(zombie_dicts)

    # Console Output (Table)
    if not args.json:
        table = Table(title=f"🧟 Zombie Report (Est. Waste: ${total_waste:.2f}/mo) 🧟")
        table.add_column("Type", style="cyan")
        table.add_column("Project")
        table.add_column("Name", style="red")
        table.add_column("Details")
        table.add_column("Est. Cost/Mo", justify="right")
        table.add_column("Reason", style="dim")

        for z in hunter.zombies:
            table.add_row(
                z.resource_type,
                z.project_id,
                z.name,
                z.details,
                f"${z.monthly_cost_est:.2f}",
                z.reason,
            )
        out_console.print(table)

    # JSON Output
    if args.json:
        print(json.dumps(zombie_dicts, indent=2))

    # CSV Output
    if args.csv:
        df.to_csv(args.csv, index=False)
        log_console.print(f"Zombie data saved to [bold]{args.csv}[/bold]")

    # HTML/PDF Report (reuse or generate)
    if args.html or args.report:
        log_console.print("\n[bold]Generating Zombie Hunter reports...[/bold]")
        try:
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            html_content = f"""
            <html>
            <head><title>Zombie Hunter Report</title><style>
            @page {{ size: A4 landscape; margin: 1cm; }}
            body {{ font-family: sans-serif; font-size: 10pt; }}
            table {{ 
                border-collapse: collapse; 
                width: 100%; 
                table-layout: fixed; /* Enforce column widths */
            }}
            th, td {{ 
                text-align: left; 
                padding: 6px; 
                border-bottom: 1px solid #ddd; 
                word-wrap: break-word; /* Wrap long text like IDs */
                overflow-wrap: break-word;
            }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            th {{ background-color: #f44336; color: white; }}
            .summary {{ background: #eee; padding: 15px; margin-bottom: 20px; }}
            
            /* Column Sizing Guide */
            th:nth-child(1) {{ width: 8%; }}  /* Type */
            th:nth-child(2) {{ width: 20%; }} /* Project */
            th:nth-child(3) {{ width: 20%; }} /* Name */
            th:nth-child(4) {{ width: 25%; }} /* Details */
            th:nth-child(5) {{ width: 10%; }} /* Cost */
            th:nth-child(6) {{ width: 17%; }} /* Reason */
            </style></head>
            <body>
            <h1>🧟 Skywalker Zombie Hunter Report</h1>
            <div class="summary">
                <p><strong>Scan Time:</strong> {scan_time}</p>
                <p><strong>Total Zombies Found:</strong> {len(hunter.zombies)}</p>
                <p><strong>Total Estimated Waste:</strong> ${total_waste:.2f}/month</p>
            </div>
            <table>
                <tr><th>Type</th><th>Project</th><th>Name</th><th>Details</th>
                <th>Est. Cost/Mo</th><th>Reason</th></tr>
            """
            for z in hunter.zombies:
                html_content += (
                    f"<tr><td>{z.resource_type}</td><td>{z.project_id}</td>"
                    f"<td>{z.name}</td><td>{z.details}</td>"
                    f"<td>${z.monthly_cost_est:.2f}</td><td>{z.reason}</td></tr>"
                )
            html_content += "</table></body></html>"

            if args.html:
                with Path(args.html).open("w") as f:
                    f.write(html_content)
                log_console.print(f"HTML Report saved to [bold]{args.html}[/bold]")

            if args.report:
                try:
                    from weasyprint import HTML

                    HTML(string=html_content).write_pdf(args.report)
                    log_console.print(f"PDF Report saved to [bold]{args.report}[/bold]")
                except ImportError:
                    log_console.print(
                        "[red]PDF Generation requires 'weasyprint'. skipping."
                    )
        except Exception as e:
            log_console.print(f"[bold red]Failed to generate report:[/bold red] {e}")
