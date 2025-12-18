from skywalker.reporter import generate_pdf


def test_generate_pdf_mock(mocker, tmp_path):
    # Mock WeasyPrint HTML class
    mock_html = mocker.patch("skywalker.reporter.HTML")

    # Sample data
    data = {
        "project_id": "test-project",
        "scan_time": "2023-01-01T00:00:00",
        "services": {
            "compute": [],
            "storage": [
                {
                    "name": "b1",
                    "size_bytes": 1024,
                    "public_access_prevention": "enforced",
                }
            ],
        },
    }

    output_file = tmp_path / "report.pdf"

    # Call the function
    generate_pdf(data, str(output_file))

    # Verify HTML was initialized and write_pdf was called
    mock_html.assert_called_once()
    mock_html.return_value.write_pdf.assert_called_once_with(str(output_file))
