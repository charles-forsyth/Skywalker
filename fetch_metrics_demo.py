import os
import time

from google.cloud import monitoring_v3

# Try to get project from env or default
project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "ucr-research-computing")

client = monitoring_v3.MetricServiceClient()
project_name = f"projects/{project_id}"

now = time.time()
seconds = int(now)
nanos = int((now - seconds) * 10**9)
interval = monitoring_v3.TimeInterval(
    {
        "end_time": {"seconds": seconds, "nanos": nanos},
        "start_time": {"seconds": (seconds - 300), "nanos": nanos},
    }
)

print(f"Fetching CPU data for: {project_id} (last 5 min)...")

try:
    results = client.list_time_series(
        request={
            "name": project_name,
            "filter": (
                'metric.type = "compute.googleapis.com/instance/cpu/utilization" '
                'AND resource.type = "gce_instance"'
            ),
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        }
    )

    count = 0
    for result in results:
        count += 1
        # Resource labels usually contain instance_id or zone
        instance_id = result.resource.labels.get("instance_id", "unknown")
        zone = result.resource.labels.get("zone", "unknown")
        pid = result.resource.labels.get("project_id", "unknown")

        # points are returned in reverse time order (newest first)
        if result.points:
            latest_point = result.points[0]
            cpu_val = latest_point.value.double_value * 100
            # CPU utilization is a double
            print(
                f"Project: {pid:<25} | "
                f"ID: {instance_id:<20} ({zone}) | "
                f"CPU: {cpu_val:>6.2f}%"
            )

    if count == 0:
        print(
            "No data found. (Check if instances are running "
            "or if the project ID is correct)"
        )

except Exception as e:
    print(f"Error: {e}")
