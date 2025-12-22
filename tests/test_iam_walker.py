
from skywalker.walkers.iam import get_iam_report


def test_get_iam_report_mock(mocker):
    # Mock Getters
    mock_get_iam = mocker.patch("skywalker.walkers.iam.get_iam_client")
    mock_iam = mock_get_iam.return_value

    mock_get_proj = mocker.patch("skywalker.walkers.iam.get_projects_client")
    mock_proj = mock_get_proj.return_value

    # Mock SA
    mock_sa = mocker.Mock()
    mock_sa.email = "test-sa@project.iam.gserviceaccount.com"
    mock_sa.unique_id = "123"
    mock_sa.display_name = "Test SA"
    mock_sa.description = "A test SA"
    mock_sa.disabled = False
    mock_iam.list_service_accounts.return_value = [mock_sa]
    mock_iam.list_service_account_keys.return_value = []

    # Mock Policy
    mock_policy = mocker.Mock()
    mock_binding = mocker.Mock()
    mock_binding.role = "roles/owner"
    mock_binding.members = ["user:admin@example.com"]
    mock_policy.bindings = [mock_binding]
    mock_proj.get_iam_policy.return_value = mock_policy

    report = get_iam_report("test-project")

    assert len(report.service_accounts) == 1
    assert report.service_accounts[0].email == "test-sa@project.iam.gserviceaccount.com"
    assert len(report.policy_bindings) == 1
    assert report.policy_bindings[0].role == "roles/owner"
