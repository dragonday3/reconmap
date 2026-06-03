import asyncio
import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from reconmap.models.asset import AssetSnapshot, Change
from reconmap.engine.scanner import Scanner
from reconmap.engine.diff import DiffEngine
from reconmap.storage.db import Storage
from reconmap.reporters.json_reporter import JSONReporter
from reconmap.reporters.html import HTMLReporter

app = typer.Typer(help="reconmap — Passive Attack Surface Intelligence Platform")
console = Console(stderr=True)

_SEV_COLOR = {
    "critical": "bold red", "high": "red",
    "medium": "yellow", "low": "blue", "info": "dim",
}


@app.command("scan")
def cmd_scan(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    github_token: str = typer.Option("", "--github-token", envvar="RECONMAP_GITHUB_TOKEN"),
    shodan_key: str = typer.Option("", "--shodan-key", envvar="RECONMAP_SHODAN_KEY"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json | html"),
    out_file: Optional[str] = typer.Option(None, "--out-file", "-f"),
    no_dns: bool = typer.Option(False, "--no-dns", help="Skip DNS brute-force"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run a passive recon scan for DOMAIN."""
    scanner = Scanner(
        github_token=github_token or None,
        shodan_key=shodan_key or None,
    )
    if not quiet:
        console.print(f"[bold cyan]reconmap[/] scanning [green]{domain}[/]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, disable=quiet) as prog:
        task = prog.add_task("Running collectors…", total=None)
        snapshot = asyncio.run(scanner.run(domain))
        prog.update(task, description=f"Done — {len(snapshot.subdomains)} subdomains, {len(snapshot.ports)} ports, {len(snapshot.leaks)} leaks")

    if not quiet:
        _print_summary(snapshot)

    _output(snapshot, [], output, out_file, quiet)

    if snapshot.leaks:
        raise typer.Exit(code=1)


@app.command("diff")
def cmd_diff(
    domain: str = typer.Argument(..., help="Target domain"),
    output: str = typer.Option("json", "--output", "-o"),
    out_file: Optional[str] = typer.Option(None, "--out-file", "-f"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    db_url: Optional[str] = typer.Option(None, "--db-url", envvar="DATABASE_URL"),
) -> None:
    """Diff the latest two snapshots stored in DB for DOMAIN."""
    async def _run():
        storage = Storage(db_url=db_url)
        await storage.init()
        try:
            snapshots = await storage.get_snapshots(domain, limit=2)
            if len(snapshots) < 2:
                console.print(f"[yellow]Need at least 2 snapshots for {domain}[/]")
                return [], None
            diff_engine = DiffEngine()
            changes = diff_engine.diff(before=snapshots[1], after=snapshots[0])
            return changes, snapshots[0]
        finally:
            await storage.close()

    changes, snapshot = asyncio.run(_run())
    if not quiet and changes:
        _print_changes(changes)
    if snapshot:
        _output(snapshot, changes, output, out_file, quiet)
    if any(c.severity in ("critical", "high") for c in changes):
        raise typer.Exit(code=1)


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    db_url: Optional[str] = typer.Option(None, "--db-url", envvar="DATABASE_URL"),
) -> None:
    """Start the reconmap REST API server."""
    import uvicorn
    if db_url:
        import os
        os.environ["DATABASE_URL"] = db_url
    uvicorn.run("reconmap.api.app:app", host=host, port=port, reload=False)


def _print_summary(snapshot: AssetSnapshot) -> None:
    if snapshot.subdomains:
        table = Table(title="Subdomains", box=box.ROUNDED)
        table.add_column("Subdomain", style="cyan")
        table.add_column("IPs")
        table.add_column("Source", style="dim")
        for sub in snapshot.subdomains[:20]:
            table.add_row(sub.subdomain, ", ".join(sub.ip_addresses) or "—", sub.source)
        if len(snapshot.subdomains) > 20:
            table.add_row(f"[dim]… {len(snapshot.subdomains)-20} more[/]", "", "")
        console.print(table)

    if snapshot.leaks:
        table = Table(title="[bold red]Secret Leaks[/]", box=box.ROUNDED)
        table.add_column("Type", style="bold red")
        table.add_column("Repo")
        table.add_column("Match (redacted)", style="dim")
        for leak in snapshot.leaks:
            table.add_row(leak.secret_type, leak.repo, leak.raw_match)
        console.print(table)


def _print_changes(changes: list[Change]) -> None:
    if not changes:
        console.print("[green]No changes.[/]")
        return
    table = Table(title="Changes", box=box.ROUNDED)
    table.add_column("Severity", min_width=8)
    table.add_column("Type")
    table.add_column("Asset", style="cyan")
    for c in changes:
        color = _SEV_COLOR.get(c.severity, "white")
        table.add_row(f"[{color}]{c.severity.upper()}[/]", c.change_type, c.asset_key)
    console.print(table)


def _output(
    snapshot: AssetSnapshot,
    changes: list[Change],
    output: str,
    out_file: Optional[str],
    quiet: bool,
) -> None:
    if output == "html":
        reporter = HTMLReporter()
        text = reporter.generate(snapshot, changes)
        if out_file:
            reporter.write(snapshot, out_file, changes)
            if not quiet:
                console.print(f"[green]Report written:[/] {out_file}")
        else:
            sys.stdout.write(text)
    else:
        reporter = JSONReporter()
        data = {"snapshot": reporter.generate(snapshot), "changes": reporter.generate_changes(changes)}
        text = json.dumps(data, indent=2, default=str)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(text)
            if not quiet:
                console.print(f"[green]Report written:[/] {out_file}")
        else:
            sys.stdout.write(text + "\n")


if __name__ == "__main__":
    app()
