import pytest

from skywalker.walkers.monitoring import fetch_fleet_metrics


def test_fetch_fleet_metrics(mocker):
    mock_get = mocker.patch("skywalker.walkers.monitoring.get_monitoring_client")
    mock_client = mock_get.return_value

    # Mock CPU response
    mock_ts = mocker.Mock()
    mock_ts.resource.labels = {
        "project_id": "lab-1",
        "instance_id": "vm-1",
        "zone": "us-central1-a",
    }
    mock_ts.points = [mocker.Mock(value=mocker.Mock(double_value=0.5))]  # 50%

    # Return CPU data, then empty for others
    mock_client.list_time_series.side_effect = [
        [mock_ts],  # CPU
        [],  # Mem
        [],  # GPU Util
        [],  # GPU Mem
    ]

    results = fetch_fleet_metrics("scoping-proj")

    assert len(results) == 1
    assert results[0]["project_id"] == "lab-1"
    assert results[0]["cpu_percent"] == 50.0
    assert "memory_percent" not in results[0]
