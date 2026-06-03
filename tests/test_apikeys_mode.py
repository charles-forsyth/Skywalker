import argparse
import json

import pytest
from rich.console import Console

from skywalker.modes.apikeys import run_api_key_audit
from skywalker.schemas.apikeys import GCPAPIKey, GCPAPIKeyUsage, GCPProjectAPIKeysReport


@pytest.fixture
def mock_consoles():
    log_console = Console(stderr=True, quiet=True)
    out_console = Console(quiet=True)
    return log_console, out_console


def test_run_api_key_audit_single_project(mocker, mock_consoles):
    log_console, out_console = mock_consoles

    # Mock walker
    mock_get_report = mocker.patch(
        "skywalker.modes.apikeys.apikeys.get_api_keys_report"
    )

    mock_report = GCPProjectAPIKeysReport(
        project_id="test-single-project",
        keys=[
            GCPAPIKey(
                name="projects/test-single-project/locations/global/keys/key-1",
                uid="key-uid-111",
                display_name="Browser Key",
                created_at="2023-01-01",
                restrictions={"HTTP Referrers": ["*.example.com/*"]},
                is_restricted=True,
                masked_key="AIzaSy...abc111",
            ),
            GCPAPIKey(
                name="projects/test-single-project/locations/global/keys/key-2",
                uid="key-uid-222",
                display_name="Server Key Unrestricted",
                created_at="2023-01-02",
                restrictions={},
                is_restricted=False,
                masked_key="AIzaSy...def222",
            ),
        ],
        usages={
            "Browser Key (AIzaSy...abc111)": [
                GCPAPIKeyUsage(
                    service="geocoding-backend.googleapis.com",
                    request_count=1000,
                    estimated_cost=5.0,
                )
            ]
        },
        total_requests=1000,
        total_estimated_cost=5.0,
    )
    mock_get_report.return_value = mock_report

    args = argparse.Namespace(
        project_id="test-single-project",
        days=30,
        sort_by="keys_count",
        json=False,
        concurrency=5,
    )

    # Capture print/out
    mocker.patch("skywalker.modes.apikeys.Console.print")

    run_api_key_audit(args, log_console, out_console)

    mock_get_report.assert_called_once_with("test-single-project", days=30)


def test_run_api_key_audit_single_project_json(mocker, capsys, mock_consoles):
    log_console, out_console = mock_consoles

    mock_get_report = mocker.patch(
        "skywalker.modes.apikeys.apikeys.get_api_keys_report"
    )
    mock_report = GCPProjectAPIKeysReport(
        project_id="test-single-project",
        keys=[],
        usages={},
        total_requests=0,
        total_estimated_cost=0.0,
    )
    mock_get_report.return_value = mock_report

    args = argparse.Namespace(
        project_id="test-single-project",
        days=30,
        sort_by="keys_count",
        json=True,
        concurrency=5,
    )

    run_api_key_audit(args, log_console, out_console)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["project_id"] == "test-single-project"
    assert data["total_requests"] == 0


def test_run_api_key_audit_fleet_scan_success(mocker, mock_consoles):
    log_console, out_console = mock_consoles

    # Mock projects list
    mock_list_projects = mocker.patch("skywalker.modes.apikeys.org.list_all_projects")
    mock_list_projects.return_value = ["proj-a", "proj-b"]

    # Mock walker
    mock_get_report = mocker.patch(
        "skywalker.modes.apikeys.apikeys.get_api_keys_report"
    )

    report_a = GCPProjectAPIKeysReport(
        project_id="proj-a",
        keys=[
            GCPAPIKey(
                name="projects/proj-a/locations/global/keys/key-1",
                uid="uid1",
                display_name="Key A",
                created_at="2023-01-01",
                is_restricted=True,
                masked_key="abc",
            )
        ],
        total_requests=10,
        total_estimated_cost=0.5,
    )
    report_b = GCPProjectAPIKeysReport(
        project_id="proj-b", keys=[], total_requests=0, total_estimated_cost=0.0
    )

    def get_report_side_effect(pid, _days):
        if pid == "proj-a":
            return report_a
        return report_b

    mock_get_report.side_effect = get_report_side_effect

    args = argparse.Namespace(
        project_id=None, days=30, sort_by="estimated_cost", json=False, concurrency=2
    )

    run_api_key_audit(args, log_console, out_console)

    assert mock_list_projects.call_count == 1
    assert mock_get_report.call_count == 2


def test_run_api_key_audit_fleet_scan_json(mocker, capsys, mock_consoles):
    log_console, out_console = mock_consoles

    mock_list_projects = mocker.patch("skywalker.modes.apikeys.org.list_all_projects")
    mock_list_projects.return_value = ["proj-a"]

    mock_get_report = mocker.patch(
        "skywalker.modes.apikeys.apikeys.get_api_keys_report"
    )
    report_a = GCPProjectAPIKeysReport(
        project_id="proj-a", keys=[], total_requests=5, total_estimated_cost=10.0
    )
    mock_get_report.return_value = report_a

    args = argparse.Namespace(
        project_id=None, days=15, sort_by="project_id", json=True, concurrency=1
    )

    run_api_key_audit(args, log_console, out_console)

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["project_id"] == "proj-a"
    assert data[0]["total_estimated_cost"] == 10.0
