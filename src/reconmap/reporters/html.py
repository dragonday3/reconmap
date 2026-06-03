import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from reconmap.models.asset import AssetSnapshot, Change


def _get_template_dir() -> Path:
    """Find the templates/ directory relative to this file."""
    here = Path(__file__).resolve()
    # src/reconmap/reporters/ -> src/reconmap/ -> src/ -> project root
    root = here.parent.parent.parent.parent
    return root / "templates"


class HTMLReporter:
    def __init__(self, template_dir: str | None = None):
        tdir = Path(template_dir) if template_dir else _get_template_dir()
        self._env = Environment(
            loader=FileSystemLoader(str(tdir)),
            autoescape=True,
        )

    def generate(self, snapshot: AssetSnapshot, changes: list[Change] | None = None) -> str:
        template = self._env.get_template("report.html.j2")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_changes = sorted(
            changes or [],
            key=lambda c: severity_order.get(c.severity, 9),
        )
        return template.render(
            snapshot=snapshot,
            changes=sorted_changes,
            total_subdomains=len(snapshot.subdomains),
            total_ports=len(snapshot.ports),
            total_leaks=len(snapshot.leaks),
            total_changes=len(sorted_changes),
        )

    def write(self, snapshot: AssetSnapshot, path: str, changes: list[Change] | None = None) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.generate(snapshot, changes))
