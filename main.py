"""
Sprint 1 — Main CLI Entry Point
Application Security & Risk Analyzer

Usage:
    python main.py <project_path> [--no-content] [--output <json_file>]

Examples:
    python main.py ./sample_project
    python main.py C:/Users/me/my_app --output results.json
"""
import argparse
import io
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

# Force UTF-8 output on Windows so rich / unicode renders correctly
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Try to import rich for coloured output; fall back to plain print ─────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.text import Text
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

from scanner import build_application_model
from scanner.models import ApplicationModel


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _plain_print(text: str) -> None:
    print(text)


def _print_banner() -> None:
    banner = (
        "\n"
        "  +=======================================================+\n"
        "  |   REC-SCAN   AI Application Security Analyzer        |\n"
        "  |   Sprint 1 -- Application Model Builder              |\n"
        "  +=======================================================+\n"
    )
    if RICH_AVAILABLE:
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    else:
        print(banner)


def _print_section(title: str) -> None:
    if RICH_AVAILABLE:
        console.rule(f"[bold yellow]{title}[/bold yellow]")
    else:
        width = 60
        print()
        print("═" * width)
        print(f"  {title}")
        print("═" * width)


def _print_folder_structure(model: ApplicationModel) -> None:
    _print_section("Folder Structure")
    if RICH_AVAILABLE:
        tree_text = "\n".join(model.folder_structure)
        console.print(Panel(tree_text, border_style="dim white", expand=False))
    else:
        for line in model.folder_structure:
            print("  " + line)


def _print_language_table(model: ApplicationModel) -> None:
    _print_section("Language Breakdown")
    if RICH_AVAILABLE:
        table = Table(show_header=True, header_style="bold magenta", expand=False)
        table.add_column("Language / Type", style="cyan", min_width=20)
        table.add_column("Files", justify="right", style="green")
        table.add_column("% of Project", justify="right", style="yellow")

        for lang, count in model.language_breakdown.items():
            pct = (count / model.file_count * 100) if model.file_count else 0
            table.add_row(lang, str(count), f"{pct:.1f}%")

        console.print(table)
    else:
        print(f"  {'Language':<25} {'Files':>6}  {'%':>6}")
        print(f"  {'-'*25} {'-'*6}  {'-'*6}")
        for lang, count in model.language_breakdown.items():
            pct = (count / model.file_count * 100) if model.file_count else 0
            print(f"  {lang:<25} {count:>6}  {pct:>5.1f}%")


def _print_summary(model: ApplicationModel, elapsed: float) -> None:
    _print_section("Application Model Summary")
    size_kb = model.total_size_bytes / 1024

    if RICH_AVAILABLE:
        summary_lines = [
            f"[bold]Project Path:[/bold]     {model.project_path}",
            f"[bold]Files Detected:[/bold]   [green]{model.file_count}[/green]",
            f"[bold]Languages:[/bold]        [cyan]{', '.join(model.languages_detected) or 'Unknown'}[/cyan]",
            f"[bold]Total Size:[/bold]       {size_kb:.1f} KB",
            f"[bold]Skipped Files:[/bold]    {len(model.skipped_files)} (binary / unreadable)",
            f"[bold]Scan Time:[/bold]        {elapsed:.2f}s",
        ]
        console.print("\n".join(summary_lines))
    else:
        print(f"  Project Path   : {model.project_path}")
        print(f"  Files Detected : {model.file_count}")
        print(f"  Languages      : {', '.join(model.languages_detected) or 'Unknown'}")
        print(f"  Total Size     : {size_kb:.1f} KB")
        print(f"  Skipped Files  : {len(model.skipped_files)} (binary / unreadable)")
        print(f"  Scan Time      : {elapsed:.2f}s")


def _save_json(model: ApplicationModel, output_path: str) -> None:
    """Serialise the ApplicationModel to JSON and save to disk."""
    # Convert dataclasses → plain dicts
    data = asdict(model)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    if RICH_AVAILABLE:
        console.print(f"\n[bold green]✔[/bold green] Application model saved → [underline]{out.resolve()}[/underline]")
    else:
        print(f"\n[OK] Application model saved → {out.resolve()}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Application Security & Risk Analyzer — Sprint 1: Application Model Builder",
    )
    parser.add_argument(
        "project_path",
        help="Path to the project directory to scan. Example: ./my_app",
    )
    parser.add_argument(
        "--no-content",
        action="store_true",
        default=False,
        help="Skip loading file content (faster, structure-only mode).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default="output/app_model.json",
        help="Where to save the JSON application model (default: output/app_model.json).",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        default=False,
        help="Do not save the JSON output.",
    )

    args = parser.parse_args()

    # Validate project path
    project_path = Path(args.project_path).resolve()
    if not project_path.exists():
        print(f"ERROR: Path does not exist: {project_path}", file=sys.stderr)
        sys.exit(1)
    if not project_path.is_dir():
        print(f"ERROR: Path is not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)

    _print_banner()

    if RICH_AVAILABLE:
        console.print(f"\n[bold]Scanning:[/bold] [yellow]{project_path}[/yellow]\n")
    else:
        print(f"\nScanning: {project_path}\n")

    # Run scan with optional progress spinner
    start_time = time.perf_counter()

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Building Application Model...", total=None)
            model = build_application_model(
                str(project_path),
                load_content=not args.no_content,
            )
            progress.update(task, completed=100, total=100)
    else:
        print("Building Application Model...")
        model = build_application_model(
            str(project_path),
            load_content=not args.no_content,
        )

    elapsed = time.perf_counter() - start_time

    # Print results
    _print_folder_structure(model)
    _print_language_table(model)
    _print_summary(model, elapsed)

    # Save JSON
    if not args.no_save:
        _save_json(model, args.output)

    if RICH_AVAILABLE:
        console.print(
            "\n[bold green]✔ Application Model Created Successfully![/bold green] "
            "[dim](No vulnerability scanning yet — Sprint 1 complete)[/dim]\n"
        )
    else:
        print("\n[OK] Application Model Created Successfully!")
        print("     (No vulnerability scanning yet — Sprint 1 complete)\n")


if __name__ == "__main__":
    main()
