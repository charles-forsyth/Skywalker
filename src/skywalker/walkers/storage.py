from google.cloud import storage  # type: ignore[attr-defined]
from tenacity import retry

from ..core import RETRY_CONFIG, memory
from ..schemas.storage import GCPBucket


@memory.cache  # type: ignore[untyped-decorator]
@retry(**RETRY_CONFIG)  # type: ignore[call-overload, untyped-decorator]
def list_buckets(project_id: str) -> list[GCPBucket]:
    """
    Lists all GCS buckets in a project with audit-relevant metadata.
    """
    storage_client = storage.Client(project=project_id)
    buckets = storage_client.list_buckets()

    results = []
    for bucket in buckets:
        # Fetch full metadata for each bucket
        # Note: list_buckets() returns some metadata, but for PAP/Uniform Access
        # we might need to ensure the bucket object is fully populated.

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
                uniform_bucket_level_access=bucket.iam_configuration.uniform_bucket_level_access_enabled,
            )
        )

    return results
