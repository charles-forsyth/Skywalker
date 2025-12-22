import pytest

from skywalker.walkers.storage import list_buckets


def test_list_buckets_mock(mocker):
    # Mock Getters
    mock_get_storage = mocker.patch("skywalker.walkers.storage.get_storage_client")
    mock_storage = mock_get_storage.return_value
    
    mock_get_monitor = mocker.patch("skywalker.walkers.storage.get_monitoring_client")
    mock_monitor = mock_get_monitor.return_value

    # Mock bucket
    mock_bucket = mocker.Mock()
    mock_bucket.name = "my-bucket"
    mock_bucket.location = "US"
    mock_bucket.storage_class = "STANDARD"
    mock_bucket.time_created = "2023-01-01"
    mock_bucket.iam_configuration.public_access_prevention = "enforced"
    mock_bucket.versioning_enabled = True
    mock_bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    
    mock_storage.list_buckets.return_value = [mock_bucket]
    
    # Mock Monitoring Response for size
    mock_ts = mocker.Mock()
    mock_ts.resource.labels = {"bucket_name": "my-bucket"}
    mock_ts.points = [mocker.Mock(value=mocker.Mock(double_value=1024.0))]
    mock_monitor.list_time_series.return_value = [mock_ts]

    results = list_buckets("test-project")

    assert len(results) == 1
    assert results[0].name == "my-bucket"
    assert results[0].size_bytes == 1024
    assert results[0].public_access_prevention == "enforced"