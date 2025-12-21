import pytest
from skywalker.core import memory
from skywalker.walkers.asset import search_all_instances

@pytest.fixture(autouse=True)
def clear_cache():
    memory.clear()

def test_search_all_instances(mocker):
    mock_client = mocker.patch("skywalker.walkers.asset.asset_v1.AssetServiceClient")
    
    # Mock Asset Response
    mock_res = mocker.Mock()
    mock_res.display_name = "test-vm"
    mock_res.location = "us-central1-a"
    mock_res.project = "projects/test-proj"
    mock_res.additional_attributes = {"id": "123", "machineType": "n1-standard-1"}
    
    mock_client.return_value.search_all_resources.return_value = [mock_res]

    results = search_all_instances("test-proj")
    
    assert len(results) == 1
    assert results["123"]["name"] == "test-vm"
    assert results["123"]["machine_type"] == "n1-standard-1"
    
    # Verify default scope handling
    mock_client.return_value.search_all_resources.assert_called_with(
        request={
            "scope": "projects/test-proj",
            "asset_types": ["compute.googleapis.com/Instance"],
            "read_mask": "name,displayName,additionalAttributes",
        }
    )
