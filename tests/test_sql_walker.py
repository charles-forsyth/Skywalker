import pytest

from skywalker.core import memory
from skywalker.walkers.sql import list_instances


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_list_sql_instances_mock(mocker):
    # Mock discovery.build
    mock_build = mocker.patch("skywalker.walkers.sql.discovery.build")

    # Mock service.instances().list().execute()
    mock_service = mock_build.return_value
    mock_instances_resource = mock_service.instances.return_value
    mock_request = mock_instances_resource.list.return_value

    # Mock Response Data (Dict)
    mock_response = {
        "items": [
            {
                "name": "test-db",
                "region": "us-west1",
                "databaseVersion": "POSTGRES_14",
                "state": "RUNNABLE",
                "settings": {"tier": "db-f1-micro", "dataDiskSizeGb": "20"},
                "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.1.2.3"}],
            }
        ]
    }

    mock_request.execute.return_value = mock_response

    # Call function
    instances = list_instances(project_id="test-project")

    # Assertions
    assert len(instances) == 1
    db = instances[0]
    assert db.name == "test-db"
    assert db.public_ip == "34.1.2.3"
    assert db.storage_limit_gb == 20

    # Verify calls
    mock_build.assert_called_with("sqladmin", "v1beta4", cache_discovery=False)
    mock_instances_resource.list.assert_called_with(project="test-project")
    mock_request.execute.assert_called_once()
