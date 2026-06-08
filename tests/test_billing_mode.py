import argparse
import csv
import json

import pytest
from rich.console import Console

from skywalker.modes.billing import is_valid_bq_table, run_billing_report


@pytest.fixture
def mock_consoles():
    log_console = Console(stderr=True, quiet=True)
    out_console = Console(quiet=True)
    return log_console, out_console


class MockRow:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_is_valid_bq_table():
    assert is_valid_bq_table("project.dataset.table") is True
    assert is_valid_bq_table("dataset.table") is True
    assert (
        is_valid_bq_table(
            "ucr-research-computing.gcp_billing."
            "gcp_billing_export_v1_01B8C7_D13B5E_17457B"
        )
        is True
    )
    assert is_valid_bq_table("invalid table; drop table") is False
    assert is_valid_bq_table("project..table") is False


def test_run_billing_report_fleet_success(mocker, mock_consoles):
    log_console, out_console = mock_consoles

    mock_client = mocker.patch("skywalker.modes.billing.get_bigquery_client")
    mock_bq_client = mocker.MagicMock()
    mock_client.return_value = mock_bq_client

    mock_row_1 = MockRow(
        project_id="proj-1",
        project_name="Project 1",
        raw_cost=150.0,
        credits=-50.0,
        net_cost=100.0,
    )
    mock_row_2 = MockRow(
        project_id="proj-2",
        project_name="Project 2",
        raw_cost=80.0,
        credits=0.0,
        net_cost=80.0,
    )
    mock_bq_client.query.return_value.result.return_value = [mock_row_1, mock_row_2]

    args = argparse.Namespace(
        project_id=None,
        days=30,
        scoping_project="test-scoping-proj",
        billing_account="01B8C7-D13B5E-17457B",
        billing_table=None,
        json=False,
        csv=None,
        html=None,
    )

    run_billing_report(args, log_console, out_console)

    mock_bq_client.query.assert_called_once()
    query_call_args = mock_bq_client.query.call_args[0][0]
    assert "project_id" in query_call_args
    assert "project_name" in query_call_args


def test_run_billing_report_project_success(mocker, mock_consoles):
    log_console, out_console = mock_consoles

    mock_client = mocker.patch("skywalker.modes.billing.get_bigquery_client")
    mock_bq_client = mocker.MagicMock()
    mock_client.return_value = mock_bq_client

    mock_row_1 = MockRow(
        service_description="Compute Engine",
        sku_description="C2 Instance",
        raw_cost=50.0,
        credits=-10.0,
        net_cost=40.0,
    )
    mock_bq_client.query.return_value.result.return_value = [mock_row_1]

    args = argparse.Namespace(
        project_id="proj-1",
        days=15,
        scoping_project="test-scoping-proj",
        billing_account="01B8C7-D13B5E-17457B",
        billing_table=None,
        json=False,
        csv=None,
        html=None,
    )

    run_billing_report(args, log_console, out_console)

    mock_bq_client.query.assert_called_once()
    query_call_args = mock_bq_client.query.call_args[0][0]
    assert "service_description" in query_call_args
    assert "sku_description" in query_call_args


def test_run_billing_report_json(mocker, capsys, mock_consoles):
    log_console, out_console = mock_consoles

    mock_client = mocker.patch("skywalker.modes.billing.get_bigquery_client")
    mock_bq_client = mocker.MagicMock()
    mock_client.return_value = mock_bq_client

    mock_row = MockRow(
        project_id="proj-json",
        project_name="Project JSON",
        raw_cost=200.0,
        credits=-50.0,
        net_cost=150.0,
    )
    mock_bq_client.query.return_value.result.return_value = [mock_row]

    args = argparse.Namespace(
        project_id=None,
        days=30,
        scoping_project="test-scoping-proj",
        billing_account="01B8C7-D13B5E-17457B",
        billing_table=None,
        json=True,
        csv=None,
        html=None,
    )

    run_billing_report(args, log_console, out_console)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["report_type"] == "fleet"
    assert data["totals"]["total_net_cost"] == 150.0
    assert len(data["rows"]) == 1
    assert data["rows"][0]["project_id"] == "proj-json"


def test_run_billing_report_csv_and_html(mocker, tmp_path, mock_consoles):
    log_console, out_console = mock_consoles

    csv_file = tmp_path / "report.csv"
    html_file = tmp_path / "report.html"

    mock_client = mocker.patch("skywalker.modes.billing.get_bigquery_client")
    mock_bq_client = mocker.MagicMock()
    mock_client.return_value = mock_bq_client

    mock_row = MockRow(
        project_id="proj-1",
        project_name="Project 1",
        raw_cost=100.0,
        credits=0.0,
        net_cost=100.0,
    )
    mock_bq_client.query.return_value.result.return_value = [mock_row]

    args = argparse.Namespace(
        project_id=None,
        days=30,
        scoping_project="test-scoping-proj",
        billing_account="01B8C7-D13B5E-17457B",
        billing_table=None,
        json=False,
        csv=str(csv_file),
        html=str(html_file),
    )

    run_billing_report(args, log_console, out_console)

    # Assert CSV exists and is formatted correctly
    assert csv_file.exists()
    with csv_file.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["project_id"] == "proj-1"
        assert float(rows[0]["net_cost"]) == 100.0

    # Assert HTML exists and rendered the template
    assert html_file.exists()
    html_content = html_file.read_text(encoding="utf-8")
    assert "Project 1" in html_content
    assert "$100.00" in html_content
