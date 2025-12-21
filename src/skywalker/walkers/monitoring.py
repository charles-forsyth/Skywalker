import time
from collections import defaultdict
from typing import Any

from google.cloud import monitoring_v3
from tenacity import retry

from ..core import RETRY_CONFIG, memory


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def fetch_fleet_metrics(scoping_project_id: str) -> list[dict[str, Any]]:
    """
    Fetches aggregated metrics for ALL projects monitored by the scoping project.
    Returns a flat list of dicts suitable for DataFrame creation.
    """
    client = monitoring_v3.MetricServiceClient()
    name = f"projects/{scoping_project_id}"

    # 10 minute window
    now = time.time()
    seconds = int(now)
    interval = monitoring_v3.TimeInterval(
        {
            "end_time": {"seconds": seconds, "nanos": 0},
            "start_time": {"seconds": seconds - 600, "nanos": 0},
        }
    )

    # Metrics map: metric_label -> filter_string
    # Note: We fetch ALL instances in the scope.
    queries = {
        "cpu_percent": (
            'metric.type = "compute.googleapis.com/instance/cpu/utilization" '
            'AND resource.type = "gce_instance"'
        ),
        "memory_percent": (
            'metric.type = "agent.googleapis.com/memory/percent_used" '
            'AND resource.type = "gce_instance"'
        ),
        "gpu_utilization": (
            'metric.type = "agent.googleapis.com/gpu/utilization" '
            'AND resource.type = "gce_instance"'
        ),
        "gpu_memory_utilization": (
            'metric.type = "agent.googleapis.com/gpu/memory/utilization" '
            'AND resource.type = "gce_instance"'
        ),
    }

    # Intermediate storage: instance_unique_id -> {data}
    # We use (project_id, instance_id) as the unique key to avoid collisions
    # if IDs repeat (rare but possible).
    fleet_data: dict[tuple[str, str], dict[str, Any]] = defaultdict(dict)

    for label, filter_str in queries.items():
        try:
            pages = client.list_time_series(
                request={
                    "name": name,
                    "filter": filter_str,
                    "interval": interval,
                    "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                }
            )
            for ts in pages:
                # Extract identifiers
                project_id = ts.resource.labels.get("project_id")
                instance_id = ts.resource.labels.get("instance_id")
                zone = ts.resource.labels.get("zone")

                if not project_id or not instance_id:
                    continue

                key = (project_id, instance_id)

                # Initialize base info if not present
                if "instance_id" not in fleet_data[key]:
                    fleet_data[key]["project_id"] = project_id
                    fleet_data[key]["instance_id"] = instance_id
                    fleet_data[key]["zone"] = zone

                # Extract value (latest point)
                if ts.points:
                    val = ts.points[0].value.double_value

                    # Normalize to 0-100 scale
                    if label in ["cpu_percent", "gpu_memory_utilization"]:
                        val *= 100

                    # Store
                    # For GPU metrics, we might get multiple streams per instance
                    # (one per GPU). We take the MAX to show "busiest component".
                    if label in fleet_data[key]:
                        fleet_data[key][label] = max(fleet_data[key][label], val)
                    else:
                        fleet_data[key][label] = val

        except Exception:
            # Squelch permission errors or partial failures
            pass

    return list(fleet_data.values())
