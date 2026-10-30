"""AegisSkill: Local CLI Security Harness against Skill-Inject Supply Chain Attacks."""

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

# If bundled with PyInstaller, configure DLL search directories for llama_cpp and native bindings
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    meipass_path = Path(sys._MEIPASS)
    llama_lib = meipass_path / "llama_cpp" / "lib"
    if hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(str(meipass_path))
        except Exception:
            pass
        if llama_lib.exists():
            try:
                os.add_dll_directory(str(llama_lib))
            except Exception:
                pass
    os.environ["PATH"] = f"{meipass_path}{os.pathsep}{llama_lib}{os.pathsep}{os.environ.get('PATH', '')}"

# Ensure standard streams handle UTF-8 properly across Windows platforms
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisskill.inference.engine import (
    ACTIVE_MODEL_NAME,
    GLOBAL_MODEL_DIR,
    get_global_model_dir,
    resolve_dynamic_model_path,
)
from aegisskill.scanner import SkillScanner

app = typer.Typer(
    name="aegis",
    help="AegisSkill: Local Security Harness protecting developers from malicious AI Agent Skills.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console(safe_box=True)


def print_banner() -> None:
    """Print the AegisSkill CLI banner."""
    banner = Text()
    banner.append("=================================================================\n", style="bold cyan")
    banner.append(" [!] AEGIS-SKILL : AI AGENT SUPPLY CHAIN SECURITY HARNESS\n", style="bold white")
    banner.append("     Deterministic Tree-Sitter AST + Local LLM Inference\n", style="dim cyan")
    banner.append("=================================================================", style="bold cyan")
    console.print(banner)


@app.command("version")
def version_command() -> None:
    """Display AegisSkill version."""
    console.print("[bold cyan]AegisSkill[/bold cyan] version 0.1.0")


@app.command("setup")
def setup_command(
    path: Path = typer.Option(
        ...,
        "--path",
        "-p",
        help="Path to the source GGUF model file (e.g. qwen3-8b.gguf or gemma-3-1b.gguf).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    copy: bool = typer.Option(
        False,
        "--copy",
        "-c",
        help="Force copy file rather than creating a symlink or hardlink.",
    ),
) -> None:
    """Configure active GGUF model for AegisSkill into ~/.aegisskill/models/active_model.gguf."""
    print_banner()
    global_dir = get_global_model_dir()
    target_path = global_dir / ACTIVE_MODEL_NAME

    console.print("\n[bold cyan]Configuring Persistent Active Model[/bold cyan]")
    console.print(f"Source Model : [white]{path}[/white]")
    console.print(f"Target Store : [white]{target_path}[/white]\n")

    # If target already exists or is broken symlink, remove it
    if target_path.exists() or target_path.is_symlink():
        try:
            target_path.unlink()
        except Exception as err:
            console.print(f"[bold red]Failed to remove existing active model:[/bold red] {err}")
            raise typer.Exit(code=1)

    method_used = "Symlink"
    if not copy:
        try:
            target_path.symlink_to(path.resolve())
        except OSError:
            # Fallback to hardlink (works on Windows NTFS without admin privileges)
            try:
                os.link(path.resolve(), target_path)
                method_used = "Hardlink"
            except OSError:
                shutil.copy2(path.resolve(), target_path)
                method_used = "File Copy"
    else:
        shutil.copy2(path.resolve(), target_path)
        method_used = "File Copy"

    setup_panel = Panel(
        f"[bold green]Active Model Successfully Configured![/bold green]\n\n"
        f"[bold]Method:[/bold] {method_used}\n"
        f"[bold]Active Model Path:[/bold] {target_path}\n"
        f"[bold]Source Path:[/bold] {path}\n\n"
        f"You can now run [bold cyan]aegis scan <skill-path>[/bold cyan] without passing --model-path.",
        title="[bold green]AEGIS SETUP : COMPLETE[/bold green]",
        border_style="green",
        box=box.ROUNDED,
    )
    console.print(setup_panel)


@app.command("scan")
def scan_command(
    target: Path = typer.Argument(
        ...,
        help="Path to the Agent Skill directory to audit (e.g. ./my-skill).",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    model_path: Optional[Path] = typer.Option(
        None,
        "--model-path",
        "-m",
        help="Path to custom GGUF model file (default: models/qwen3-8b-instruct.gguf).",
    ),
    fast: bool = typer.Option(
        False,
        "--fast",
        help="Use lightweight qwen2.5-coder-1.5b-instruct-q4_k_m.gguf for low-spec laptops.",
    ),
    dry_run_mock: bool = typer.Option(
        False,
        "--dry-run-mock",
        help="Bypass local LLM inference and use deterministic mock evaluation (hackathon fallback).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print detailed AST extraction log and prompt sent to the LLM.",
    ),
) -> None:
    """Audit an Agent Skill directory for malicious backdoors and data exfiltration."""
    print_banner()

    # Initialize Scanner
    try:
        with console.status("[bold green]Initializing Aegis AST parser & engine...", spinner="dots"):
            scanner = SkillScanner(
                model_path=model_path,
                fast_mode=fast,
                dry_run_mock=dry_run_mock,
            )
    except Exception as exc:
        console.print(f"[bold red]Initialization Error:[/bold red] {exc}")
        raise typer.Exit(code=2)

    resolved_name = (
        Path(scanner.config.model_path).name if scanner.config.model_path else "Unknown"
    )
    model_display = (
        "[yellow]Mock Mode (Bypassing LLM)[/yellow]"
        if dry_run_mock
        else (
            f"[magenta]Fast ({resolved_name})[/magenta]"
            if fast
            else f"[blue]{resolved_name}[/blue] [dim]({scanner.config.model_path})[/dim]"
        )
    )

    console.print(f"\n[bold]Target Directory:[/bold] {target}")
    console.print(f"[bold]Inference Profile:[/bold] {model_display}")
    console.print(f"[bold]Context Budget:[/bold] [yellow]2048 tokens strictly enforced[/yellow]\n")

    # Execute Scan with visual spinner
    with console.status("[bold cyan]Scanning Agent Skill: Parsing SKILL.md & AST nodes...", spinner="bouncingBar"):
        try:
            result = scanner.scan(target)
        except Exception as exc:
            console.print(f"[bold red]Scan Failure:[/bold red] {exc}")
            raise typer.Exit(code=2)

    # 1. Print Metadata & Overview
    meta_table = Table(box=box.ROUNDED, show_header=False, expand=True)
    meta_table.add_column("Key", style="bold cyan", width=22)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("Skill Name", escape(result.metadata.name))
    meta_table.add_row("Stated Purpose", escape(result.metadata.description or "No description provided"))
    meta_table.add_row("Python Files Scanned", escape(", ".join(result.ast_result.files_scanned) or "None found"))
    meta_table.add_row("AST Artifacts Extracted", str(result.ast_result.total_artifacts))
    meta_table.add_row("Scan Latency", f"{result.duration_seconds:.2f}s")

    console.print(Panel(meta_table, title="[bold]Skill Metadata & AST Ingestion Summary[/bold]", border_style="cyan"))

    # 2. Print Extracted AST Findings
    ast_table = Table(
        title="Deterministic AST Findings (High-Risk Invocations Only)",
        box=box.HEAVY_EDGE,
        expand=True,
    )
    ast_table.add_column("Category", style="cyan", width=16)
    ast_table.add_column("Risk", width=10)
    ast_table.add_column("Location", style="yellow", width=24)
    ast_table.add_column("Extracted Code Snippet", style="white")

    all_findings = (
        result.ast_result.network_calls
        + result.ast_result.os_calls
        + result.ast_result.other_risks
        + result.ast_result.imports
    )

    if all_findings:
        for item in all_findings:
            risk_style = (
                "[bold red]CRITICAL[/bold red]"
                if item.risk_level == "CRITICAL"
                else (
                    "[red]HIGH[/red]"
                    if item.risk_level == "HIGH"
                    else ("[yellow]MEDIUM[/yellow]" if item.risk_level == "MEDIUM" else "[dim]LOW[/dim]")
                )
            )
            loc = f"{item.source_file}:{item.line_number}"
            code_preview = item.raw_code.replace("\n", " ")[:70]
            ast_table.add_row(item.category, risk_style, loc, escape(code_preview))
        console.print(ast_table)
    else:
        console.print("[dim green][OK] No suspicious AST invocations detected.[/dim green]")

    # 3. Verbose prompt details if requested
    if verbose:
        console.print(
            Panel(
                result.prompt_used,
                title="[bold yellow]Context Window Sent to LLM (Strict 2048 Limit)[/bold yellow]",
                border_style="yellow",
            )
        )

    # 4. Final Security Report Panel & Exit Code
    report = result.report
    console.print("\n" + "=" * 65)

    if report.is_safe:
        content = Text()
        content.append("VERDICT: SAFE TO LOAD\n\n", style="bold green")
        content.append("Threat Category: ", style="bold")
        content.append(f"{report.threat_category}\n", style="bold green")
        content.append("Explanation: ", style="bold")
        content.append(f"{report.vulnerability_explanation}\n\n", style="white")
        content.append("Structured Pydantic JSON Report:\n", style="bold cyan")
        content.append(f"{report.model_dump_json(indent=2)}\n", style="dim cyan")

        verdict_panel = Panel(
            content,
            title="[bold green]AEGIS SECURITY CLEARANCE : PASS[/bold green]",
            border_style="green",
            box=box.ROUNDED,
        )
        console.print(verdict_panel)
        console.print("[bold green]Skill cleared for execution. Exiting with code 0.[/bold green]\n")
        raise typer.Exit(code=0)
    else:
        content = Text()
        content.append("VERDICT: THREAT DETECTED - EXECUTION BLOCKED\n\n", style="bold red")
        content.append("Threat Category: ", style="bold red")
        content.append(f"{report.threat_category}\n", style="bold red")
        content.append("Vulnerability Explanation: ", style="bold")
        content.append(f"{report.vulnerability_explanation}\n\n", style="white")
        content.append("Structured Pydantic JSON Threat Report:\n", style="bold cyan")
        content.append(f"{report.model_dump_json(indent=2)}\n\n", style="dim cyan")
        content.append("Action: ", style="bold yellow")
        content.append("Do not load this skill into agent tools. Quarantine or inspect source code immediately.", style="yellow")

        verdict_panel = Panel(
            content,
            title="[bold red]AEGIS SECURITY ALERT : BLOCKED[/bold red]",
            border_style="red",
            box=box.ROUNDED,
        )
        console.print(verdict_panel)
        console.print("[bold red]Untrusted skill identified. Exiting with code 1.[/bold red]\n")
        raise typer.Exit(code=1)


def main() -> None:
    """CLI script entrypoint."""
    app()


if __name__ == "__main__":
    main()
