import time

from google.cloud import monitoring_v3
from tenacity import retry

from ..clients import get_monitoring_client, get_storage_client
from ..core import RETRY_CONFIG
from ..logger import logger
from ..schemas.storage import GCPBucket


def fetch_bucket_sizes(project_id: str) -> dict[str, int]:
    """
    Fetches the total bytes for all buckets in the project using Cloud Monitoring.
    Returns a dict mapping bucket_name -> size_in_bytes.
    """
    client = get_monitoring_client()
    project_name = f"projects/{project_id}"

    # Query 'storage.googleapis.com/storage/total_bytes' for the last 24h
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

    # Aggregation: Group by bucket_name and take the MAX
    aggregation = monitoring_v3.Aggregation(
        {
            "alignment_period": {"seconds": 86400},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_MAX,
            "cross_series_reducer": monitoring_v3.Aggregation.Reducer.REDUCE_NONE,
            "group_by_fields": ["resource.label.bucket_name"],
        }
    )

    sizes = {}
    try:
        results = client.list_time_series(
            request={
                "name": project_name,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation,
            }
        )

        for series in results:
            bucket_name = series.resource.labels["bucket_name"]
            if series.points:
                sizes[bucket_name] = int(series.points[0].value.double_value)
    except Exception as e:
        logger.debug(f"Failed to fetch bucket sizes for {project_id}: {e}")

    return sizes


@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_buckets(project_id: str) -> list[GCPBucket]:
    """
    Lists all GCS buckets in a project with audit-relevant metadata.
    """
    results = []
    try:
        storage_client = get_storage_client()
        # Note: we don't pass project to storage.Client() anymore as it's shared,
        # but we use list_buckets(project=project_id)
        buckets = storage_client.list_buckets(project=project_id)

        # Fetch sizes in bulk
        bucket_sizes = fetch_bucket_sizes(project_id)

        for bucket in buckets:
            size = bucket_sizes.get(bucket.name, 0)
            results.append(
                GCPBucket(
                    name=bucket.name,
                    location=bucket.location,
                    storage_class=bucket.storage_class,
                    creation_timestamp=bucket.time_created,
                    public_access_prevention=(
                        bucket.iam_configuration.public_access_prevention
                        or "unspecified"
                    ),
                    versioning_enabled=bucket.versioning_enabled,
                    uniform_bucket_level_access=(
                        bucket.iam_configuration.uniform_bucket_level_access_enabled
                    ),
                    size_bytes=size,
                )
            )
    except Exception as e:
        logger.warning(f"Failed to list buckets for {project_id}: {e}")

    return results