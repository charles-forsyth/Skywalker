import pytest
from unittest.mock import MagicMock
from skywalker.modes.fix import _install_agent, _fix_ops_agent

def test_install_agent_success(mocker):
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value.returncode = 0
    
    instance = {
        "instance_name": "vm-1",
        "zone": "us-central1-a",
        "project_id": "proj-1"
    }
    
    result = _install_agent(instance)
    assert "SUCCESS" in result
    
    # Verify command structure
    cmd = mock_run.call_args[0][0]
    assert "gcloud" in cmd
    assert "compute" in cmd
    assert "ssh" in cmd
    assert "vm-1" in cmd
    assert "--tunnel-through-iap" in cmd

def test_install_agent_skip_gke(mocker):
    mock_run = mocker.patch("subprocess.run")
    
    instance = {
        "instance_name": "gke-node-pool-1",
        "zone": "us-central1-a",
        "project_id": "proj-1"
    }
    
    result = _install_agent(instance)
    assert "Skipping" in result
    assert "GKE Node" in result
    mock_run.assert_not_called()

def test_fix_ops_agent_flow(mocker):
    # Mock deps
    mock_fetch = mocker.patch("skywalker.walkers.monitoring.fetch_fleet_metrics")
    mock_asset = mocker.patch("skywalker.walkers.asset.search_all_instances")
    mock_confirm = mocker.patch("rich.prompt.Confirm.ask")
    mock_install = mocker.patch("skywalker.modes.fix._install_agent")
    
    mock_console = MagicMock()
    mock_args = MagicMock()
    mock_args.monitor = True
    mock_args.scoping_project = "scope"
    
    # Setup data: 1 candidate
    mock_fetch.return_value = [
        {"project_id": "p1", "instance_id": "1", "cpu_percent": 50.0, "memory_percent": None}
    ]
    mock_asset.return_value = {
        "1": {"name": "vm-1", "machine_type": "n1"}
    }
    
    # User says YES
    mock_confirm.return_value = True
    mock_install.return_value = "SUCCESS"
    
    _fix_ops_agent(mock_args, mock_console)
    
    mock_install.assert_called_once()
    args = mock_install.call_args[0][0]
    assert args["instance_name"] == "vm-1"
