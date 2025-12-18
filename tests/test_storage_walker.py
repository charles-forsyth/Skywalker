from datetime import datetime, timezone

import pytest

from skywalker.core import memory
from skywalker.walkers.storage import list_buckets


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_list_buckets_mock(mocker):
    # Mock the Storage Client
    mock_client = mocker.patch("skywalker.walkers.storage.storage.Client")

    # Create a mock bucket object
    mock_bucket = mocker.Mock()
    mock_bucket.name = "test-bucket"
    mock_bucket.location = "US-WEST1"
    mock_bucket.storage_class = "STANDARD"
    mock_bucket.time_created = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_bucket.versioning_enabled = True

    # Mock IAM Configuration
    mock_iam = mocker.Mock()
    mock_iam.public_access_prevention = "enforced"
    mock_iam.uniform_bucket_level_access_enabled = True
    mock_bucket.iam_configuration = mock_iam

    # Configure the mock client to return the mock bucket
    mock_client.return_value.list_buckets.return_value = [mock_bucket]

    # Call the function
    buckets = list_buckets(project_id="test-project")

    # Assertions
    assert len(buckets) == 1
    b = buckets[0]
    assert b.name == "test-bucket"
    assert b.public_access_prevention == "enforced"
    assert b.versioning_enabled is True
    assert b.uniform_bucket_level_access is True

    # Verify the client was called correctly
    mock_client.assert_called_once_with(project="test-project")
    mock_client.return_value.list_buckets.assert_called_once()
