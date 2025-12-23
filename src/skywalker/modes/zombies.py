from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

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
                if addr.status == "RESERVED" and not addr.user:
                    self.zombies.append(
                        ZombieResource(
                            resource_type="Static IP",
                            project_id=project_id,
                            name=addr.name,
                            details=addr.address,
                            monthly_cost_est=7.30,
                            reason="Reserved but not in use",
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

            # Fetch activity (this is slow, so maybe skip for V1 or optimize)
            # For V1, let's just list empty buckets? No, empty buckets cost $0.
            # We want FULL buckets that are idle.
            # Let's verify Monitoring API access first.
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
            # Including buckets in the hunt
            futures.append(executor.submit(hunter.hunt_buckets, pid))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.debug(f"Hunter task failed: {e}")

    # 3. Report
    if not hunter.zombies:
        out_console.print("[green]No Zombies Found! Fleet is clean.[/green]")
        return

    # Sort by cost desc
    hunter.zombies.sort(key=lambda z: z.monthly_cost_est, reverse=True)

    total_waste = sum(z.monthly_cost_est for z in hunter.zombies)

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
