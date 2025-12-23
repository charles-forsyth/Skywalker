import time
from collections import defaultdict
from typing import Any

from google.api_core import exceptions
from google.cloud import monitoring_v3
from tenacity import retry

from ..clients import get_monitoring_client
from ..core import RETRY_CONFIG
from ..logger import logger


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def fetch_fleet_metrics(scoping_project_id: str) -> list[dict[str, Any]]:
    """
    Fetches aggregated metrics for ALL projects monitored by the scoping project.
    Returns a flat list of dicts suitable for DataFrame creation.
    """
    client = get_monitoring_client()
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

        except exceptions.PermissionDenied:
            logger.warning(
                f"Permission denied fetching metric {label} from scope {name}"
            )
        except exceptions.GoogleAPICallError as e:
            logger.warning(f"Metric API error for {label}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in metric fetch {label}: {e}")

    return list(fleet_data.values())


def fetch_inactive_resources(
    project_id: str,
    metric_type: str,
    resource_type: str,
    days: int = 30,
    group_by: list[str] | None = None,
) -> dict[str, float]:
    """
    Fetches the SUM of a metric over a long period to detect inactivity.
    Returns: {resource_name: total_value}
    
    If total_value == 0, the resource is inactive (Zombie).
    """
    client = get_monitoring_client()
    name = f"projects/{project_id}"
    
    now = time.time()
    seconds = int(now)
    start_seconds = seconds - (days * 86400)
    
    interval = monitoring_v3.TimeInterval(
        {
            "end_time": {"seconds": seconds, "nanos": 0},
            "start_time": {"seconds": start_seconds, "nanos": 0},
        }
    )
    
    filter_str = (
        f'metric.type = "{metric_type}" AND resource.type = "{resource_type}"'
    )
    
    # Aggregation: Align by summing over the entire period
    # Note: 30 days is a huge window. We must use a large alignment period.
    alignment_period = {"seconds": days * 86400}
    
    if not group_by:
        # Default grouping depends on resource type usually, but we need
        # the resource identifier labels.
        # For buckets: resource.label.bucket_name
        # For SQL: resource.label.database_id
        # For Filestore: resource.label.instance_id
        pass

    aggregation = monitoring_v3.Aggregation(
        {
            "alignment_period": alignment_period,
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            "cross_series_reducer": monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
            "group_by_fields": group_by,
        }
    )
    
    results = {}
    try:
        pages = client.list_time_series(
            request={
                "name": name,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation,
            }
        )
        for ts in pages:
            # Identifier logic depends on what we grouped by
            # Usually the first label in the group_by list is the key
            if not ts.points:
                continue
                
            val = ts.points[0].value.double_value or float(ts.points[0].value.int64_value)
            
            # Key construction
            # If we grouped by ["resource.label.bucket_name"], 
            # we check ts.resource.labels["bucket_name"]
            # But the Aggregation API puts grouped labels in metric/resource labels of the output.
            
            # Helper to find the key
            key = "unknown"
            if group_by:
                # Try to find the value of the first grouping field in labels
                field = group_by[0]
                label_key = field.split(".")[-1]
                key = ts.resource.labels.get(label_key) or ts.metric.labels.get(label_key) or "unknown"
            
            results[key] = val
            
    except Exception as e:
        logger.debug(f"Failed to fetch inactivity metric {metric_type}: {e}")
        
    return results