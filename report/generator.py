"""
generator.py
------------
Renders a ScanSummary into a professional HTML (and optionally PDF) report
using the Jinja2 template in report/templates/report.html.
"""

import logging
import subprocess
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"
DEFAULT_OUTPUT_DIR = Path("output")


class ReportGenerator:
    """Renders vulnerability findings into a styled HTML/PDF report."""

    def __init__(self, output_dir: str | Path = DEFAULT_OUTPUT_DIR) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def generate_html(self, summary, filename: str | None = None) -> Path:
        """Render the HTML report and write it to output_dir."""
        template = self.env.get_template("report.html")

        ctx = {
            "summary": summary,
            "report_date": datetime.now().strftime("%d %B %Y"),
        }

        html = template.render(**ctx)
        out_path = self.output_dir / (filename or self._default_filename(summary.target, "html"))
        out_path.write_text(html, encoding="utf-8")
        logger.info("HTML report saved → %s", out_path)
        return out_path

    def generate_pdf(self, summary, filename: str | None = None) -> Path | None:
        """
        Convert the HTML report to PDF using WeasyPrint (if installed).
        Falls back gracefully if WeasyPrint or its system libraries are unavailable.
        On Windows, WeasyPrint requires GTK which is often not present — in that
        case we skip silently and the HTML report remains available.
        """
        html_path = self.generate_html(summary)
        pdf_path = html_path.with_suffix(".pdf")

        # Try WeasyPrint — catch ImportError AND OSError (missing GTK on Windows)
        try:
            from weasyprint import HTML  # type: ignore
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info("PDF report saved → %s", pdf_path)
            return pdf_path
        except ImportError:
            logger.debug("WeasyPrint not installed, trying wkhtmltopdf…")
        except OSError as e:
            logger.warning(
                "WeasyPrint could not load system libraries (common on Windows): %s\n"
                "Trying wkhtmltopdf fallback…", e
            )
        except Exception as e:
            logger.warning("WeasyPrint failed unexpectedly (%s), trying wkhtmltopdf…", e)

        # Fallback: wkhtmltopdf CLI
        try:
            subprocess.run(
                ["wkhtmltopdf", "--quiet", str(html_path), str(pdf_path)],
                check=True,
                capture_output=True,
            )
            logger.info("PDF report saved → %s", pdf_path)
            return pdf_path
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning(
                "PDF generation skipped — neither WeasyPrint nor wkhtmltopdf is available.\n"
                "Your HTML report is ready at: %s\n"
                "To enable PDF export on Windows, see: https://wkhtmltopdf.org/downloads.html",
                html_path,
            )
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_filename(target: str, ext: str) -> str:
        slug = target.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"report_{slug}_{ts}.{ext}"
