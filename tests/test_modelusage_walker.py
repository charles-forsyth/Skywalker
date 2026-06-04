import pytest
from google.api_core import exceptions as google_exceptions

from skywalker.schemas.modelusage import GCPProjectModelUsageReport
from skywalker.walkers.modelusage import (
    find_model_pricing,
    get_model_usage_report,
    load_pricing_info,
)


def test_load_pricing_info_file_not_found(mocker):
    # If the file does not exist, it falls back to the default list
    mocker.patch("os.path.exists", return_value=False)
    pricing = load_pricing_info()
    assert len(pricing) > 0
    assert any(p["pattern"] == "gemini-1.5-flash" for p in pricing)
    assert any(p["pattern"] == "default" for p in pricing)


def test_find_model_pricing():
    pricing = [
        {
            "pattern": "gemini-1.5-flash",
            "input": 0.075,
            "output": 0.30,
            "blended": 0.15,
        },
        {
            "pattern": "gemini-1.5-pro",
            "input": 1.25,
            "output": 5.00,
            "blended": 2.50,
        },
        {"pattern": "default", "input": 0.0, "output": 0.0, "blended": 0.0},
    ]

    match_flash = find_model_pricing("v1/gemini-1.5-flash-preview", pricing)
    assert match_flash["pattern"] == "gemini-1.5-flash"
    assert match_flash["input"] == 0.075

    match_pro = find_model_pricing("models/gemini-1.5-pro-002", pricing)
    assert match_pro["pattern"] == "gemini-1.5-pro"
    assert match_pro["output"] == 5.00

    match_unknown = find_model_pricing("some-custom-model-id", pricing)
    assert match_unknown["pattern"] == "default"
    assert match_unknown["input"] == 0.0


def test_get_model_usage_report_success(mocker):
    # Mock monitoring client getter
    mock_get_monitoring = mocker.patch(
        "skywalker.walkers.modelusage.get_monitoring_client"
    )
    mock_client = mocker.Mock()
    mock_get_monitoring.return_value = mock_client

    # Mock load_pricing_info
    mocker.patch(
        "skywalker.walkers.modelusage.load_pricing_info",
        return_value=[
            {
                "pattern": "gemini-1.5-flash",
                "input": 0.10,
                "output": 0.40,
                "blended": 0.20,
            },
            {
                "pattern": "gemini-1.5-pro",
                "input": 1.00,
                "output": 4.00,
                "blended": 2.00,
            },
            {"pattern": "default", "input": 0.0, "output": 0.0, "blended": 0.0},
        ],
    )

    # Mock Point class structures
    class MockPointValue:
        def __init__(self, int_val=None, dbl_val=None):
            self.int64_value = int_val
            self.double_value = dbl_val

    class MockPoint:
        def __init__(self, val):
            self.value = val

    class MockLabels:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class MockTimeSeries:
        def __init__(self, resource_labels, metric_labels, points):
            self.resource = mocker.Mock()
            self.resource.labels = resource_labels
            self.metric = mocker.Mock()
            self.metric.labels = metric_labels
            self.points = points

        def get(self, attr, default=None):
            return getattr(self, attr, default)

    # Timeseries for Invocations
    ts_inv_flash = MockTimeSeries(
        resource_labels={"model_user_id": "gemini-1.5-flash", "publisher": "google"},
        metric_labels={},
        points=[MockPoint(MockPointValue(int_val=1000))],
    )
    ts_inv_pro = MockTimeSeries(
        resource_labels={"model_user_id": "gemini-1.5-pro", "publisher": "google"},
        metric_labels={},
        points=[MockPoint(MockPointValue(int_val=500))],
    )

    # Timeseries for Tokens
    ts_tok_flash_in = MockTimeSeries(
        resource_labels={"model_user_id": "gemini-1.5-flash", "publisher": "google"},
        metric_labels={"type": "input"},
        points=[MockPoint(MockPointValue(int_val=2_000_000))],  # 2M tokens
    )
    ts_tok_flash_out = MockTimeSeries(
        resource_labels={"model_user_id": "gemini-1.5-flash", "publisher": "google"},
        metric_labels={"type": "output"},
        points=[MockPoint(MockPointValue(int_val=3_000_000))],  # 3M tokens
    )
    ts_tok_pro_in = MockTimeSeries(
        resource_labels={"model_user_id": "gemini-1.5-pro", "publisher": "google"},
        metric_labels={"type": "input"},
        points=[
            MockPoint(MockPointValue(dbl_val=500_000.0))
        ],  # 0.5M tokens (as double)
    )
    ts_tok_pro_out = MockTimeSeries(
        resource_labels={"model_user_id": "gemini-1.5-pro", "publisher": "google"},
        metric_labels={"type": "output"},
        points=[MockPoint(MockPointValue(int_val=1_000_000))],  # 1M tokens
    )

    def list_ts_side_effect(request):
        filt = request.get("filter", "")
        if "model_invocation_count" in filt:
            return [ts_inv_flash, ts_inv_pro]
        if "token_count" in filt:
            return [ts_tok_flash_in, ts_tok_flash_out, ts_tok_pro_in, ts_tok_pro_out]
        return []

    mock_client.list_time_series.side_effect = list_ts_side_effect

    # Run walker
    report = get_model_usage_report("test-project", days=30)

    assert isinstance(report, GCPProjectModelUsageReport)
    assert report.project_id == "test-project"
    assert report.total_requests == 1500
    assert report.total_input_tokens == 2_500_000
    assert report.total_output_tokens == 4_000_000

    # Cost Calculation check:
    # flash: input_tokens=2M, rate=0.10/M -> $0.20
    #        output_tokens=3M, rate=0.40/M -> $1.20
    #        cost = $1.40
    # pro:   input_tokens=0.5M, rate=1.00/M -> $0.50
    #        output_tokens=1M, rate=4.00/M -> $4.00
    #        cost = $4.50
    # Total cost = $5.90
    assert report.total_estimated_cost == 5.90

    assert len(report.usages) == 2
    # Sorted by cost descending, so gemini-1.5-pro should be first
    assert report.usages[0].model_id == "gemini-1.5-pro"
    assert report.usages[0].estimated_cost == 4.50
    assert report.usages[1].model_id == "gemini-1.5-flash"
    assert report.usages[1].estimated_cost == 1.40


def test_get_model_usage_report_failures_ignored(mocker):
    mock_get_monitoring = mocker.patch(
        "skywalker.walkers.modelusage.get_monitoring_client"
    )
    mock_client = mocker.Mock()
    mock_get_monitoring.return_value = mock_client

    # Make list_time_series throw a generic exception to be ignored
    mock_client.list_time_series.side_effect = Exception("Generic connection issue")

    report = get_model_usage_report("test-project", days=30)
    assert report.project_id == "test-project"
    assert len(report.usages) == 0
    assert report.total_requests == 0
    assert report.total_estimated_cost == 0.0


def test_get_model_usage_report_retry_on_google_server_error(mocker):
    # Mock sleep so retry is instant
    mocker.patch("time.sleep", return_value=None)

    mock_get_monitoring = mocker.patch(
        "skywalker.walkers.modelusage.get_monitoring_client"
    )
    mock_client = mocker.Mock()
    mock_get_monitoring.return_value = mock_client

    # list_time_series raises google exception 500 (InternalServerError)
    mock_client.list_time_series.side_effect = google_exceptions.InternalServerError(
        "Server error"
    )

    import tenacity

    with pytest.raises(tenacity.RetryError):
        get_model_usage_report("test-project", days=30)

    # 3 attempts according to RETRY_CONFIG
    assert mock_client.list_time_series.call_count == 3
