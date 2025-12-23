from skywalker.walkers.sql import list_instances


def test_list_sql_instances_mock(mocker):
    # Mock Getter
    mock_get = mocker.patch("skywalker.walkers.sql.get_sql_client")
    mock_service = mock_get.return_value

    mock_inst = {
        "name": "mydb",
        "region": "us-west1",
        "databaseVersion": "POSTGRES_15",
        "state": "RUNNABLE",
        "ipAddresses": [{"type": "PRIMARY", "ipAddress": "1.2.3.4"}],
        "settings": {"tier": "db-f1-micro", "dataDiskSizeGb": "10"},
    }

    mock_service.instances.return_value.list.return_value.execute.return_value = {
        "items": [mock_inst]
    }

    results = list_instances("test-project")
    assert len(results) == 1
    assert results[0].name == "mydb"
    assert results[0].public_ip == "1.2.3.4"
    assert results[0].storage_limit_gb == 10
