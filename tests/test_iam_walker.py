from datetime import datetime

import pytest

from skywalker.core import memory
from skywalker.walkers.iam import get_iam_report


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear joblib caching for all tests in this module."""
    memory.clear()


def test_get_iam_report_mock(mocker):
    # Mock IAM Client
    mock_iam_client = mocker.patch("skywalker.walkers.iam.iam_admin_v1.IAMClient")

    # Mock Service Account
    mock_sa = mocker.Mock()
    mock_sa.email = "sa@test-project.iam.gserviceaccount.com"
    mock_sa.unique_id = "12345"
    mock_sa.display_name = "Test SA"
    mock_sa.description = "Test Description"
    mock_sa.disabled = False

    # Mock Keys
    mock_key = mocker.Mock()
    mock_key.name = "projects/test-project/serviceAccounts/sa@.../keys/key1"
    mock_key.key_type.name = "USER_MANAGED"
    mock_key.valid_after_time = datetime(2023, 1, 1)
    mock_key.valid_before_time = datetime(2024, 1, 1)

    mock_iam_client.return_value.list_service_accounts.return_value = [mock_sa]
    mock_iam_client.return_value.list_service_account_keys.return_value = [mock_key]

    # Mock Resource Manager Client
    mock_rm_client = mocker.patch(
        "skywalker.walkers.iam.resourcemanager_v3.ProjectsClient"
    )
    mocker.patch("skywalker.walkers.iam.iam_policy_pb2.GetIamPolicyRequest")

    # Mock Policy
    mock_policy = mocker.Mock()
    mock_binding = mocker.Mock()
    mock_binding.role = "roles/owner"
    mock_binding.members = ["user:admin@example.com"]
    mock_policy.bindings = [mock_binding]

    mock_rm_client.return_value.get_iam_policy.return_value = mock_policy

    # Call function
    report = get_iam_report(project_id="test-project")

    # Assertions
    assert len(report.service_accounts) == 1
    sa = report.service_accounts[0]
    assert sa.email == "sa@test-project.iam.gserviceaccount.com"
    assert len(sa.keys) == 1
    assert sa.keys[0].name == "key1"

    assert len(report.policy_bindings) == 1
    binding = report.policy_bindings[0]
    assert binding.role == "roles/owner"
    assert binding.members == ["user:admin@example.com"]
