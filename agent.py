#!/usr/bin/env python3
"""
DevOps Repository Auditing Agent CLI Entry Point.
Complies with Section 5 and Section 8 of the assignment specification:
Usage:
    python agent.py --repo <github_repository_url> --output report.json
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Load local environment variables from .env if present
load_dotenv()

from agent_core.cloner import ClonerError, RepoWorkspace
from agent_core.llm_client import create_llm_client
from agent_core.loop import DevOpsAgentLoop
from agent_core.schemas import AuditReport
from tools import RepoInspectionTools


def configure_logging(verbose: bool = False) -> None:
    """Configures structured logging."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_cli_summary(report: AuditReport) -> None:
    """Prints a clean terminal summary of detected violations."""
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console(highlight=False)
        console.print(f"\n[bold green][OK] DevOps Repository Audit Complete[/bold green]")
        console.print(f"[bold cyan]Repository:[/bold cyan] {report.repository}")
        console.print(f"[bold cyan]Total Violations Detected:[/bold cyan] {len(report.violations)}\n")

        if not report.violations:
            console.print("[green]No DevOps violations detected. Repository appears healthy![/green]\n")
            return

        table = Table(title="Detected DevOps Violations", show_header=True, header_style="bold magenta")
        table.add_column("Rule ID", style="cyan", width=10)
        table.add_column("Category", style="yellow", width=22)
        table.add_column("Severity", style="bold red", width=10)
        table.add_column("File:Line", style="dim", width=25)
        table.add_column("Description", width=40)

        for v in report.violations:
            loc = f"{v.file or '-'}:{v.line or '-'}"
            sev_color = {
                "critical": "[bold red]critical[/bold red]",
                "high": "[red]high[/red]",
                "medium": "[yellow]medium[/yellow]",
                "low": "[blue]low[/blue]",
            }.get(v.severity.value, v.severity.value)

            table.add_row(v.rule_id, v.category, sev_color, loc, v.description[:38] + ("..." if len(v.description) > 38 else ""))

        console.print(table)
        console.print()
    except ImportError:
        # Fallback to standard console print
        print(f"\nAudit complete for: {report.repository}")
        print(f"Total violations detected: {len(report.violations)}")
        for v in report.violations:
            loc = f"{v.file or '-'}:{v.line or '-'}"
            print(f"[{v.rule_id}] {v.severity.upper()} | {loc} | {v.description}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Autonomous AI Agent for DevOps Repository Auditing and Best-Practice Inspection."
    )
    parser.add_argument(
        "--repo",
        type=str,
        required=True,
        help="Target public GitHub repository URL (e.g. https://github.com/owner/repo) or local path.",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Destination path for the generated audit JSON report (e.g. report.json).",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default=None,
        help="LLM provider: gemini (default free, 15 RPM/1.5k RPD via Google AI Studio), groq, openrouter, openai, or offline.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model name (e.g. gemini-1.5-flash, gemini-2.0-flash, llama-3.3-70b-versatile, gpt-4o-mini).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=int(os.environ.get("DEFAULT_MAX_STEPS", "12")),
        help="Maximum agent reasoning steps (default: 12).",
    )
    parser.add_argument(
        "--temp-dir",
        type=str,
        default=None,
        help="Optional custom base directory for repository clone isolation.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline deterministic mode with zero API calls (ideal for CI and automated test verification).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed logging output.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    configure_logging(args.verbose)

    repo_url = args.repo.strip()
    output_path = Path(args.output).resolve()

    # Step 1: Select LLM Client
    provider = "offline" if args.offline else args.provider
    try:
        llm_client = create_llm_client(provider=provider, model=args.model)
    except Exception as exc:
        sys.stderr.write(f"Configuration Error: {exc}\n")
        return 1

    # Step 2: Clone repository safely into isolated workspace
    try:
        with RepoWorkspace(repo_url, custom_temp_dir=args.temp_dir) as workspace_path:
            # Step 3: Bind tools to isolated workspace
            tools = RepoInspectionTools(workspace_path)

            # Step 4: Run Agent Loop
            agent = DevOpsAgentLoop(
                repository_url=repo_url,
                tools=tools,
                llm_client=llm_client,
                max_steps=args.max_steps,
            )
            report = agent.run()

            # Step 5: Write JSON report according to exact contract
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report.to_json(indent=2))

            print_cli_summary(report)
            logging.info(f"Audit report successfully written to: {output_path}")
            return 0

    except ClonerError as ce:
        sys.stderr.write(f"Repository Error: {ce}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"Fatal Agent Error: {exc}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
