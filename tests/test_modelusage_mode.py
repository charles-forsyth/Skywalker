import argparse
import json

import pytest
from rich.console import Console

from skywalker.modes.modelusage import run_model_audit
from skywalker.schemas.modelusage import GCPModelUsage, GCPProjectModelUsageReport


@pytest.fixture
def mock_consoles():
    log_console = Console(stderr=True, quiet=True)
    out_console = Console(quiet=True)
    return log_console, out_console


def test_run_model_audit_single_project(mocker, mock_consoles):
    log_console, out_console = mock_consoles

    # Mock walker
    mock_get_report = mocker.patch(
        "skywalker.modes.modelusage.modelusage.get_model_usage_report"
    )

    mock_report = GCPProjectModelUsageReport(
        project_id="test-single-project",
        usages=[
            GCPModelUsage(
                model_id="gemini-1.5-flash",
                publisher="google",
                request_count=1000,
                input_tokens=500_000,
                output_tokens=1_000_000,
                estimated_cost=0.3375,
            ),
            GCPModelUsage(
                model_id="gemini-1.5-pro",
                publisher="google",
                request_count=100,
                input_tokens=100_000,
                output_tokens=200_000,
                estimated_cost=1.125,
            ),
        ],
        total_requests=1100,
        total_input_tokens=600_000,
        total_output_tokens=1_200_000,
        total_estimated_cost=1.46,
    )
    mock_get_report.return_value = mock_report

    args = argparse.Namespace(
        project_id="test-single-project",
        days=30,
        sort_by="estimated_cost",
        json=False,
        concurrency=5,
    )

    mocker.patch("skywalker.modes.modelusage.Console.print")

    run_model_audit(args, log_console, out_console)

    mock_get_report.assert_called_once_with("test-single-project", days=30)


def test_run_model_audit_single_project_json(mocker, capsys, mock_consoles):
    log_console, out_console = mock_consoles

    mock_get_report = mocker.patch(
        "skywalker.modes.modelusage.modelusage.get_model_usage_report"
    )
    mock_report = GCPProjectModelUsageReport(
        project_id="test-single-project",
        usages=[],
        total_requests=0,
        total_estimated_cost=0.0,
    )
    mock_get_report.return_value = mock_report

    args = argparse.Namespace(
        project_id="test-single-project",
        days=30,
        sort_by="estimated_cost",
        json=True,
        concurrency=5,
    )

    run_model_audit(args, log_console, out_console)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["project_id"] == "test-single-project"
    assert data["total_requests"] == 0
    assert len(data["usages"]) == 0


def test_run_model_audit_fleet_scan_success(mocker, mock_consoles):
    log_console, out_console = mock_consoles

    # Mock projects list
    mock_list_projects = mocker.patch(
        "skywalker.modes.modelusage.org.list_all_projects"
    )
    mock_list_projects.return_value = ["proj-a", "proj-b"]

    # Mock walker
    mock_get_report = mocker.patch(
        "skywalker.modes.modelusage.modelusage.get_model_usage_report"
    )

    report_a = GCPProjectModelUsageReport(
        project_id="proj-a",
        usages=[
            GCPModelUsage(
                model_id="gemini-1.5-flash",
                publisher="google",
                request_count=100,
                input_tokens=10000,
                output_tokens=20000,
                estimated_cost=0.5,
            )
        ],
        total_requests=100,
        total_input_tokens=10000,
        total_output_tokens=20000,
        total_estimated_cost=0.5,
    )
    report_b = GCPProjectModelUsageReport(
        project_id="proj-b",
        usages=[],
        total_requests=0,
        total_estimated_cost=0.0,
    )

    def get_report_side_effect(pid, _days):
        if pid == "proj-a":
            return report_a
        return report_b

    mock_get_report.side_effect = get_report_side_effect

    args = argparse.Namespace(
        project_id=None,
        days=30,
        sort_by="estimated_cost",
        json=False,
        concurrency=2,
    )

    run_model_audit(args, log_console, out_console)

    assert mock_list_projects.call_count == 1
    assert mock_get_report.call_count == 2


def test_run_model_audit_fleet_scan_json(mocker, capsys, mock_consoles):
    log_console, out_console = mock_consoles

    mock_list_projects = mocker.patch(
        "skywalker.modes.modelusage.org.list_all_projects"
    )
    mock_list_projects.return_value = ["proj-a"]

    mock_get_report = mocker.patch(
        "skywalker.modes.modelusage.modelusage.get_model_usage_report"
    )
    report_a = GCPProjectModelUsageReport(
        project_id="proj-a",
        usages=[],
        total_requests=5,
        total_estimated_cost=10.0,
    )
    mock_get_report.return_value = report_a

    args = argparse.Namespace(
        project_id=None,
        days=15,
        sort_by="project_id",
        json=True,
        concurrency=1,
    )

    run_model_audit(args, log_console, out_console)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["project_id"] == "proj-a"
    assert data[0]["total_estimated_cost"] == 10.0
