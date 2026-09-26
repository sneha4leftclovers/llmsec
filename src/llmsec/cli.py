"""Command line interface for llmsec."""

import json
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from llmsec import __version__

app = typer.Typer(
    name="llmsec",
    help="Evidence-first LLM security assessment CLI for authorized security testing.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


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


# --------------------------------------------------------------------------- #
# init command                                                                 #
# --------------------------------------------------------------------------- #

@app.command("init")
def init_command(
    output: Path = typer.Option(
        Path("llmsec_config.yaml"),
        "--output",
        "-o",
        help="Path to write the example configuration file.",
    ),
) -> None:
    """Generate an example llmsec configuration file."""
    from llmsec.config_loader import write_example_config
    from llmsec.errors import ConfigurationError

    if output.exists():
        overwrite = typer.confirm(
            f"File '{output}' already exists. Overwrite?",
            default=False,
        )
        if not overwrite:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(0)

    try:
        write_example_config(str(output))
        console.print(f"[green]✓[/green] Example config written to [cyan]{output}[/cyan]")
        console.print("Edit the file, then run: [bold]llmsec scan --config {output}[/bold]")
    except ConfigurationError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# scan command                                                                 #
# --------------------------------------------------------------------------- #

@app.command("scan")
def scan_command(
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to assessment configuration file (YAML).",
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Directory to save scan_result.json and optional report.",
    ),
    suites: Optional[List[str]] = typer.Option(
        None,
        "--suites",
        "-s",
        help="Override selected test suites (e.g. --suites canary --suites authz).",
    ),
    report: bool = typer.Option(
        False,
        "--report",
        help="Also generate an HTML report at <output>/report.html.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Load and validate configuration only. Do not run probes.",
    ),
) -> None:
    """Execute an authorized security assessment scan against a target LLM endpoint."""
    from llmsec.config_loader import load_config
    from llmsec.errors import ConfigurationError
    from llmsec.scanner import Scanner

    if config is None:
        err_console.print(
            "[bold red]Error:[/bold red] --config is required. "
            "Run `llmsec init --output myconfig.yaml` to create one."
        )
        raise typer.Exit(1)

    # 1. Load and validate config
    try:
        cfg = load_config(str(config))
    except ConfigurationError as exc:
        err_console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        raise typer.Exit(1)

    # 2. Override suites if provided on CLI
    if suites:
        cfg = cfg.model_copy(update={"selected_test_suites": suites})

    console.print(
        f"[bold cyan]llmsec scan[/bold cyan] — target: [cyan]{cfg.target_url}[/cyan] "
        f"suites: [green]{cfg.selected_test_suites}[/green]"
    )

    if dry_run:
        console.print("[green]✓ Dry run complete. Configuration is valid.[/green]")
        raise typer.Exit(0)

    # 3. Run the scan
    try:
        result = Scanner(cfg).run()
    except Exception as exc:
        err_console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        raise typer.Exit(1)

    # 4. Save outputs
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        result_path = output / "scan_result.json"
        result_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]✓[/green] Scan result saved to [cyan]{result_path}[/cyan]")

        if report:
            _generate_html_report(result, cfg, output / "report.html")

    # 5. Print summary
    _print_scan_summary(result)


def _generate_html_report(result: "ScanResult", cfg: "LLMSecConfig", report_path: Path) -> None:
    """Generate an HTML report from the ScanResult findings."""
    from llmsec.errors import IntegrationError, ReportError
    from llmsec.report import ReportGenerator

    try:
        gen = ReportGenerator(findings=result.findings, config=cfg)
        gen.render_html(str(report_path))
        console.print(f"[green]✓[/green] HTML report saved to [cyan]{report_path}[/cyan]")
    except (ReportError, IntegrationError) as exc:
        err_console.print(f"[yellow]Warning:[/yellow] Report generation failed: {exc}")


def _print_scan_summary(result: "ScanResult") -> None:
    """Print a Rich summary table of the scan result."""
    total = len(result.findings)
    deterministic = sum(1 for f in result.findings if f.is_deterministic)
    model_judged = sum(1 for f in result.findings if f.is_model_judged)

    console.print()
    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Total findings", str(total))
    table.add_row("Confirmed deterministic", str(deterministic))
    table.add_row("Model judged", str(model_judged))
    table.add_row("Canary token matches", str(len(result.canary_findings)))
    table.add_row("Authz findings", str(len(result.authz_findings)))
    table.add_row("Skipped suites", ", ".join(result.skipped_suites) or "none")
    table.add_row("Errors", str(len(result.errors)))
    console.print(table)

    if result.errors:
        console.print()
        console.print("[bold yellow]Errors collected during scan:[/bold yellow]")
        for err in result.errors:
            console.print(f"  [red]•[/red] {err}")

    console.print(f"\n[dim]Run ID: {result.run_id}[/dim]")


# Type aliases for the helper functions above (avoids forward reference issues)
from llmsec.models import ScanResult  # noqa: E402
from llmsec.config import LLMSecConfig  # noqa: E402


# --------------------------------------------------------------------------- #
# report command                                                               #
# --------------------------------------------------------------------------- #

@app.command("report")
def report_command(
    findings_file: Path = typer.Option(
        ...,
        "--findings",
        "-f",
        help="Path to scan_result.json generated by `llmsec scan`.",
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("report.html"),
        "--output",
        "-o",
        help="Output path for the generated report.",
    ),
    format: str = typer.Option(
        "html",
        "--format",
        help="Report format: 'html' or 'pdf'.",
    ),
) -> None:
    """Generate a structured HTML or PDF security assessment report from scan findings."""
    from llmsec.config import AuthorizationConfig, LLMSecConfig
    from llmsec.errors import ConfigurationError, IntegrationError, ReportError
    from llmsec.models import ScanResult
    from llmsec.report import ReportGenerator

    # 1. Load ScanResult from JSON
    if not findings_file.exists():
        err_console.print(f"[bold red]Error:[/bold red] Findings file not found: '{findings_file}'")
        raise typer.Exit(1)

    try:
        data = json.loads(findings_file.read_text(encoding="utf-8"))
        result = ScanResult(**data)
    except (json.JSONDecodeError, Exception) as exc:
        err_console.print(f"[bold red]Error loading findings:[/bold red] {exc}")
        raise typer.Exit(1)

    # 2. Build a minimal config from the scan result for the report generator
    try:
        cfg = LLMSecConfig(
            target_url=result.config_target_url,
            authorization=AuthorizationConfig(authorized=True),
        )
    except Exception as exc:
        err_console.print(f"[bold red]Error building report config:[/bold red] {exc}")
        raise typer.Exit(1)

    # 3. Generate report
    gen = ReportGenerator(findings=result.findings, config=cfg)
    fmt = format.lower().strip()

    try:
        if fmt == "html":
            gen.render_html(str(output))
            console.print(f"[green]✓[/green] HTML report written to [cyan]{output}[/cyan]")
        elif fmt == "pdf":
            gen.render_pdf(str(output))
            console.print(f"[green]✓[/green] PDF report written to [cyan]{output}[/cyan]")
        else:
            err_console.print(f"[bold red]Error:[/bold red] Unknown format '{fmt}'. Use 'html' or 'pdf'.")
            raise typer.Exit(1)
    except IntegrationError as exc:
        err_console.print(f"[bold red]Integration error:[/bold red] {exc}")
        raise typer.Exit(1)
    except ReportError as exc:
        err_console.print(f"[bold red]Report error:[/bold red] {exc}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
