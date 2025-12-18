from pathlib import Path
from typing import Any

import humanize
import jinja2
from weasyprint import HTML


def generate_pdf(report_data: dict[str, Any], output_path: str) -> None:
    """
    Generates a PDF report from the gathered audit data.
    """
    # Calculate totals for summary
    total_bytes = 0
    if "storage" in report_data.get("services", {}):
        for b in report_data["services"]["storage"]:
            total_bytes += b.get("size_bytes") or 0

    # Setup Jinja2 environment
    template_dir = Path(__file__).parent / "templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(template_dir)),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
    )

    # Register custom filter for humanize
    env.filters["humanize_size"] = lambda v: humanize.naturalsize(v) if v else "0 Bytes"

    # Render HTML
    template = env.get_template("report.html")
    html_content = template.render(data=report_data, total_bytes=total_bytes)

    # Generate PDF
    HTML(string=html_content).write_pdf(output_path)
