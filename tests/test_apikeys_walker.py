import pytest
from googleapiclient.errors import HttpError

from skywalker.schemas.apikeys import GCPProjectAPIKeysReport
from skywalker.walkers.apikeys import get_api_keys_report


class MockResponse:
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason


def test_get_api_keys_report_success(mocker):
    # Mock the central client factory getters
    mock_get_apikeys = mocker.patch("skywalker.walkers.apikeys.get_apikeys_client")
    mock_get_monitoring = mocker.patch(
        "skywalker.walkers.apikeys.get_monitoring_client"
    )

    # 1. Setup API Keys client mock
    mock_apikeys_client = mocker.Mock()
    mock_get_apikeys.return_value = mock_apikeys_client

    mock_list_req = mocker.Mock()
    mock_list_req.execute.return_value = {
        "keys": [
            {
                "name": "projects/test-project/locations/global/keys/key-1",
                "uid": "key-1-uid-123456",
                "displayName": "Restricted Geocoding Key",
                "createTime": "2023-01-01T00:00:00Z",
                "restrictions": {
                    "apiTargets": [{"service": "geocoding-backend.googleapis.com"}],
                    "browserKeyRestrictions": {"allowedReferrers": ["*.example.com/*"]},
                },
            },
            {
                "name": "projects/test-project/locations/global/keys/key-2",
                "uid": "key-2-uid-789012",
                "displayName": "Unrestricted Dangerous Key",
                "createTime": "2023-01-02T00:00:00Z",
                "restrictions": {},
            },
        ]
    }

    mock_proj = mock_apikeys_client.projects.return_value
    mock_locs = mock_proj.locations.return_value
    mock_keys_client = mock_locs.keys.return_value
    mock_keys_client.list.return_value = mock_list_req

    # Mock getKeyString responses
    mock_get_str_req1 = mocker.Mock()
    mock_get_str_req1.execute.return_value = {
        "keyString": "AIzaSyKey1GeocodingKeyStringValue"
    }
    mock_get_str_req2 = mocker.Mock()
    mock_get_str_req2.execute.return_value = {
        "keyString": "AIzaSyKey2UnrestrictedKeyStringValue"
    }

    def get_key_string_side_effect(name):
        if "key-1" in name:
            return mock_get_str_req1
        return mock_get_str_req2

    mock_keys_client.getKeyString.side_effect = get_key_string_side_effect

    # 2. Setup Monitoring client mock
    mock_monitoring_client = mocker.Mock()
    mock_get_monitoring.return_value = mock_monitoring_client

    # Define mock time series
    mock_ts1 = mocker.Mock()
    mock_ts1.metric.labels = {"credential_id": "apikey:key-1-uid-123456"}
    mock_ts1.resource.labels = {"service": "geocoding-backend.googleapis.com"}
    pt1 = mocker.Mock()
    pt1.value.int64_value = 5000  # 5,000 requests
    pt1.value.double_value = None
    mock_ts1.points = [pt1]

    mock_ts2 = mocker.Mock()
    mock_ts2.metric.labels = {"credential_id": "apikey:key-2"}  # matches split name
    mock_ts2.resource.labels = {"service": "translate.googleapis.com"}
    pt2 = mocker.Mock()
    pt2.value.int64_value = None
    pt2.value.double_value = 2000.0  # 2,000 requests as double
    mock_ts2.points = [pt2]

    mock_monitoring_client.list_time_series.return_value = [mock_ts1, mock_ts2]

    # Run the walker
    report = get_api_keys_report("test-project", days=30)

    # Validate report output
    assert isinstance(report, GCPProjectAPIKeysReport)
    assert report.project_id == "test-project"
    assert len(report.keys) == 2

    # Verify key-1 (Restricted)
    k1 = report.keys[0]
    assert k1.display_name == "Restricted Geocoding Key"
    assert k1.uid == "key-1-uid-123456"
    assert k1.is_restricted is True
    assert "API Targets (Scoped)" in k1.restrictions
    assert "HTTP Referrers" in k1.restrictions
    assert k1.masked_key == "AIzaSy...gValue"

    # Verify key-2 (Unrestricted)
    k2 = report.keys[1]
    assert k2.display_name == "Unrestricted Dangerous Key"
    assert k2.uid == "key-2-uid-789012"
    assert k2.is_restricted is False
    assert k2.restrictions == {}
    assert k2.masked_key == "AIzaSy...gValue"

    # Verify usages are aggregated
    # Total requests: 5,000 (geocoding) + 2,000 (translate) = 7,000
    assert report.total_requests == 7000

    # Total estimated cost:
    # 5,000 requests for geocoding-backend = (5000 / 1000) * 5.00 = 25.00
    # 2,000 requests for translate = (2000 / 1000) * 20.00 = 40.00
    # Total = 65.00
    assert report.total_estimated_cost == 65.00

    # Verify usage keys mapped correctly to key display names
    assert "Restricted Geocoding Key (AIzaSy...gValue)" in report.usages
    assert "Unrestricted Dangerous Key (AIzaSy...gValue)" in report.usages

    usage1 = report.usages["Restricted Geocoding Key (AIzaSy...gValue)"][0]
    assert usage1.service == "geocoding-backend.googleapis.com"
    assert usage1.request_count == 5000
    assert usage1.estimated_cost == 25.0

    usage2 = report.usages["Unrestricted Dangerous Key (AIzaSy...gValue)"][0]
    assert usage2.service == "translate.googleapis.com"
    assert usage2.request_count == 2000
    assert usage2.estimated_cost == 40.0


def test_get_api_keys_report_permission_denied(mocker):
    # Verify that listing permission denied errors are handled gracefully
    mock_get_apikeys = mocker.patch("skywalker.walkers.apikeys.get_apikeys_client")
    mock_get_monitoring = mocker.patch(
        "skywalker.walkers.apikeys.get_monitoring_client"
    )

    mock_apikeys_client = mocker.Mock()
    mock_get_apikeys.return_value = mock_apikeys_client

    # Mock list keys throwing HttpError 403
    resp = MockResponse(403, "Permission Denied")
    mock_proj = mock_apikeys_client.projects.return_value
    mock_locs = mock_proj.locations.return_value
    mock_keys_client = mock_locs.keys.return_value
    mock_keys_client.list.return_value.execute.side_effect = HttpError(
        resp=resp, content=b"Permission Denied"
    )

    mock_monitoring_client = mocker.Mock()
    mock_get_monitoring.return_value = mock_monitoring_client
    mock_monitoring_client.list_time_series.return_value = []

    report = get_api_keys_report("test-project", days=30)
    assert report.project_id == "test-project"
    assert len(report.keys) == 0
    assert report.total_requests == 0
    assert report.total_estimated_cost == 0.0


def test_get_api_keys_report_retry_on_503(mocker):
    # Mock time.sleep to run instantly
    mocker.patch("time.sleep", return_value=None)

    # Verify we raise HttpError on 503 for tenacity to retry
    mock_get_apikeys = mocker.patch("skywalker.walkers.apikeys.get_apikeys_client")
    mock_apikeys_client = mocker.Mock()
    mock_get_apikeys.return_value = mock_apikeys_client

    resp = MockResponse(503, "Service Unavailable")
    mock_proj = mock_apikeys_client.projects.return_value
    mock_locs = mock_proj.locations.return_value
    mock_keys_client = mock_locs.keys.return_value
    mock_execute = mock_keys_client.list.return_value.execute
    mock_execute.side_effect = HttpError(resp=resp, content=b"Service Unavailable")

    import tenacity

    # Use pytest.raises to make sure RetryError is raised after max attempts
    with pytest.raises(tenacity.RetryError):
        get_api_keys_report("test-project", days=30)

    # Verify we retried 3 times (the stop limit in RETRY_CONFIG)
    assert mock_execute.call_count == 3
