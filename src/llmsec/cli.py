"""Command line interface for llmsec."""

from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from llmsec import __version__

app = typer.Typer(
    name="llmsec",
    help="Evidence-first LLM security assessment CLI for authorized security testing.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]llmsec[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show llmsec version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """llmsec: Evidence-first LLM application security assessment CLI."""


@app.command("scan")
def scan_command(
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to assessment configuration file (YAML or JSON).",
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    target_url: Optional[str] = typer.Option(
        None,
        "--target-url",
        "-u",
        help="Target LLM endpoint URL (must be authorized).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save raw findings and telemetry (JSON format).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate configuration and test connectivity without executing probes.",
    ),
) -> None:
    """Execute an authorized security assessment scan against a target LLM endpoint."""
    console.print("[bold yellow]llmsec scan[/bold yellow] (Foundation / Placeholder)")
    console.print(
        "[dim]Note: Active scanning engine is scheduled for subsequent phases. "
        "The configuration and finding models are validated in Phase 1.[/dim]"
    )
    if config:
        console.print(f"Provided config path: [cyan]{config}[/cyan]")
    if target_url:
        console.print(f"Provided target URL: [cyan]{target_url}[/cyan]")
    if dry_run:
        console.print("[green]Dry run flag detected: Configuration parsing is active.[/green]")


@app.command("report")
def report_command(
    findings_file: Path = typer.Option(
        ...,
        "--findings",
        "-f",
        help="Path to JSON findings file generated from an llmsec scan.",
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("report.html"),
        "--output",
        "-o",
        help="Output destination path for the generated report (HTML or PDF).",
    ),
    format: str = typer.Option(
        "html",
        "--format",
        help="Report export format ('html' or 'pdf').",
    ),
) -> None:
    """Generate a structured HTML or PDF security assessment report from scan findings."""
    console.print("[bold yellow]llmsec report[/bold yellow] (Foundation / Placeholder)")
    console.print(
        "[dim]Note: Jinja2 and WeasyPrint report rendering pipeline will be implemented in a subsequent phase. "
        f"Findings file referenced: {findings_file}[/dim]"
    )


if __name__ == "__main__":
    app()
