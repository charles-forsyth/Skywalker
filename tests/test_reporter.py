from datetime import datetime

from skywalker.reporter import generate_compliance_report
from skywalker.schemas.iam import GCPIAMReport, GCPPolicyBinding, GCPServiceAccount
from skywalker.schemas.storage import GCPBucket


def test_generate_compliance_report_mock(mocker, tmp_path):
    # Mock WeasyPrint HTML class
    mock_html = mocker.patch("skywalker.reporter.HTML")

    # Sample fleet data (list of project dicts)
    data = [
        {
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
    ]

    output_file = tmp_path / "report.pdf"

    # Call the function
    generate_compliance_report(data, str(output_file), output_format="pdf")

    # Verify HTML was initialized and write_pdf was called
    mock_html.assert_called_once()
    mock_html.return_value.write_pdf.assert_called_once_with(str(output_file))


def test_generate_compliance_report_html(tmp_path):
    # Sample fleet data
    data = [
        {
            "project_id": "test-project",
            "scan_time": datetime(2023, 1, 1),
            "services": {"compute": [], "storage": []},
        }
    ]

    output_file = tmp_path / "report.html"

    # Call the function for HTML
    generate_compliance_report(data, str(output_file), output_format="html")

    # Verify file was written
    assert output_file.exists()
    assert "test-project" in output_file.read_text()
