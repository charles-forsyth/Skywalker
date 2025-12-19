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
    def humanize_size_filter(v: int | None) -> str:
        if not v:
            return "0 Bytes"
        return str(humanize.naturalsize(v))

    env.filters["humanize_size"] = humanize_size_filter

    def format_date(value: Any) -> str:
        if isinstance(value, str):
            # Assume ISO format and just take the date part
            return value.split("T")[0]
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d")  # type: ignore[no-any-return]
        return str(value)

    env.filters["format_date"] = format_date

    # Render HTML
    template = env.get_template("report.html")
    html_content = template.render(data=report_data, total_bytes=total_bytes)

    # Generate PDF
    HTML(string=html_content).write_pdf(output_path)
