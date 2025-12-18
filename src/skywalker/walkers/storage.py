import time

from google.cloud import monitoring_v3, storage  # type: ignore[attr-defined]
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.storage import GCPBucket


@memory.cache  # type: ignore[untyped-decorator]
def fetch_bucket_sizes(project_id: str) -> dict[str, int]:
    """
    Fetches the total bytes for all buckets in the project using Cloud Monitoring.
    Returns a dict mapping bucket_name -> size_in_bytes.
    """
    client = monitoring_v3.MetricServiceClient()
    project_name = f"projects/{project_id}"

    # Query 'storage.googleapis.com/storage/total_bytes' for the last 24h
    # We aggregate by resource.bucket_name and take the latest value (GAUGE metric)
    now = time.time()
    seconds = int(now)
    nanos = int((now - seconds) * 10**9)

    interval = monitoring_v3.TimeInterval(
        {
            "end_time": {"seconds": seconds, "nanos": nanos},
            "start_time": {"seconds": seconds - 86400, "nanos": nanos},
        }
    )

    # Filter for total_bytes metric
    filter_str = (
        'metric.type = "storage.googleapis.com/storage/total_bytes" '
        'AND resource.type = "gcs_bucket"'
    )

    # Aggregation: Group by bucket_name and take the MAX (peak usage today)
    aggregation = monitoring_v3.Aggregation(
        {
            "alignment_period": {"seconds": 86400},  # 24 hours
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_MAX,
            "cross_series_reducer": monitoring_v3.Aggregation.Reducer.REDUCE_NONE,
            "group_by_fields": ["resource.label.bucket_name"],
        }
    )

    results = client.list_time_series(
        request={
            "name": project_name,
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        }
    )

    sizes = {}
    for series in results:
        bucket_name = series.resource.labels["bucket_name"]
        # The points are ordered by time desc, so index 0 is the latest/max
        if series.points:
            sizes[bucket_name] = int(series.points[0].value.double_value)

    return sizes


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_buckets(project_id: str) -> list[GCPBucket]:
    """
    Lists all GCS buckets in a project with audit-relevant metadata.
    """
    storage_client = storage.Client(project=project_id)
    buckets = storage_client.list_buckets()

    # Fetch sizes in bulk
    try:
        bucket_sizes = fetch_bucket_sizes(project_id)
    except Exception as e:
        print(f"Warning: Could not fetch bucket sizes: {e}")
        bucket_sizes = {}

    results = []
    for bucket in buckets:
        # Fetch full metadata for each bucket
        # Note: list_buckets() returns some metadata, but for PAP/Uniform Access
        # we might need to ensure the bucket object is fully populated.

        size = bucket_sizes.get(bucket.name, 0)

        results.append(
            GCPBucket(
                name=bucket.name,
                location=bucket.location,
                storage_class=bucket.storage_class,
                creation_timestamp=bucket.time_created,
                public_access_prevention=(
                    bucket.iam_configuration.public_access_prevention or "unspecified"
                ),
                versioning_enabled=bucket.versioning_enabled,
                uniform_bucket_level_access=(
                    bucket.iam_configuration.uniform_bucket_level_access_enabled
                ),
                size_bytes=size,
            )
        )

    return results
