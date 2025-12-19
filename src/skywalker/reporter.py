from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import humanize
import jinja2
from weasyprint import HTML


def generate_fleet_report(
    fleet_data: list[dict[str, Any]],
    output_path: str,
    output_format: Literal["html", "pdf"] = "pdf",
) -> None:
    """
    Generates a consolidated audit report for multiple projects.
    """
    # Setup Jinja2 environment
    template_dir = Path(__file__).parent / "templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(template_dir)),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
    )

    # Register custom filters
    def humanize_size_filter(v: int | None) -> str:
        if not v:
            return "0 Bytes"
        return str(humanize.naturalsize(v))

    def format_date(value: Any) -> str:
        if isinstance(value, str):
            return value.split("T")[0]
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d")  # type: ignore[no-any-return]
        return str(value)

    env.filters["humanize_size"] = humanize_size_filter
    env.filters["format_date"] = format_date

    # Render HTML
    template = env.get_template("report.html")
    html_content = template.render(
        fleet_data=fleet_data, scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    if output_format == "html":
        Path(output_path).write_text(html_content, encoding="utf-8")
    else:
        # Generate PDF
        HTML(string=html_content).write_pdf(output_path)
