from datetime import datetime

from skywalker.reporter import generate_pdf
from skywalker.schemas.iam import GCPIAMReport, GCPPolicyBinding, GCPServiceAccount
from skywalker.schemas.storage import GCPBucket


def test_generate_pdf_mock(mocker, tmp_path):
    # Mock WeasyPrint HTML class
    mock_html = mocker.patch("skywalker.reporter.HTML")

    # Sample data
    data = {
        "project_id": "test-project",
        "scan_time": datetime(2023, 1, 1),
        "services": {
            "compute": [],
            "storage": [
                GCPBucket(
                    name="b1",
                    location="US",
                    storage_class="STANDARD",
                    creation_timestamp=datetime(2023, 1, 1),
                    size_bytes=1024,
                    public_access_prevention="enforced",
                )
            ],
            "iam": GCPIAMReport(
                service_accounts=[
                    GCPServiceAccount(
                        email="test-sa@example.com",
                        unique_id="123",
                        display_name="Test SA",
                        description="Test",
                        disabled=False,
                    )
                ],
                policy_bindings=[
                    GCPPolicyBinding(
                        role="roles/owner", members=["user:admin@example.com"]
                    )
                ],
            ),
        },
    }

    output_file = tmp_path / "report.pdf"

    # Call the function
    generate_pdf(data, str(output_file))

    # Verify HTML was initialized and write_pdf was called
    mock_html.assert_called_once()
    mock_html.return_value.write_pdf.assert_called_once_with(str(output_file))
