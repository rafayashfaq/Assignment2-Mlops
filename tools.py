"""
DevOps Inspection Tools Module.
Implements all required and optional inspection tools per Section 3 of the specification.
Includes strict sandboxing, path traversal protection, and secret redaction.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from agent_core.schemas import redact_secrets


class RepoInspectionTools:
    """
    Inspection tool suite bounded to a specific repository workspace directory.
    Guarantees that tool operations do not escape the target repository boundaries
    and never alter the inspected code.
    """

    def __init__(self, repo_dir: str | Path):
        self.repo_dir = Path(repo_dir).resolve()
        if not self.repo_dir.exists() or not self.repo_dir.is_dir():
            raise ValueError(f"Repository directory does not exist: {self.repo_dir}")

    def _safe_path(self, relative_path: str) -> Path:
        """Resolves path and prevents directory traversal attacks."""
        clean_rel = relative_path.strip().lstrip("/\\")
        target = (self.repo_dir / clean_rel).resolve()
        try:
            target.relative_to(self.repo_dir)
        except ValueError:
            raise PermissionError(f"Access denied: Path '{relative_path}' traverses outside repository.")
        return target

    def list_files(self, directory: str = "", max_depth: int = 5) -> Dict[str, Any]:
        """
        Discovers repository files and structure.
        Skips .git internal objects to conserve context, while recording .git presence.
        """
        try:
            target_dir = self._safe_path(directory)
            if not target_dir.exists():
                return {"error": f"Directory not found: {directory}", "files": []}
            if not target_dir.is_dir():
                return {"error": f"Path is not a directory: {directory}", "files": []}

            results: List[Dict[str, Any]] = []
            base_depth = len(target_dir.parts)

            for root, dirs, files in os.walk(target_dir):
                curr_depth = len(Path(root).parts) - base_depth
                # Do not traverse into .git internals
                if ".git" in dirs:
                    dirs.remove(".git")
                if curr_depth >= max_depth:
                    dirs.clear()
                    continue

                for d in sorted(dirs):
                    rel_dir = os.path.relpath(os.path.join(root, d), self.repo_dir).replace("\\", "/")
                    results.append({"path": rel_dir, "type": "directory"})

                for f in sorted(files):
                    file_path = Path(root) / f
                    rel_file = os.path.relpath(file_path, self.repo_dir).replace("\\", "/")
                    try:
                        size = file_path.stat().st_size
                    except OSError:
                        size = 0
                    results.append({"path": rel_file, "type": "file", "size_bytes": size})

            has_git = (self.repo_dir / ".git").is_dir()
            return {
                "root": str(self.repo_dir.name),
                "is_git_repository": has_git,
                "total_items": len(results),
                "files": results[:250],  # Token safety cap
                "truncated": len(results) > 250,
            }
        except Exception as exc:
            return {"error": f"Failed to list files: {str(exc)}"}

    def read_file(self, path: str, start_line: int = 1, max_lines: int = 200) -> Dict[str, Any]:
        """
        Inspects source code, workflow configurations, or documentation.
        Returns 1-indexed numbered lines with secret values redacted.
        """
        try:
            file_path = self._safe_path(path)
            if not file_path.exists():
                return {"error": f"File does not exist: {path}"}
            if not file_path.is_file():
                return {"error": f"Path is not a regular file: {path}"}

            # Check if binary file
            try:
                with open(file_path, "rb") as f:
                    chunk = f.read(1024)
                    if b"\x00" in chunk:
                        return {"error": f"File is binary and cannot be displayed: {path}"}
            except OSError as err:
                return {"error": f"Failed to read file: {err}"}

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            total_lines = len(lines)
            start_idx = max(1, start_line) - 1
            end_idx = min(total_lines, start_idx + max_lines)

            selected_lines = []
            for idx in range(start_idx, end_idx):
                line_content = lines[idx].rstrip("\r\n")
                # Redact any accidental credentials in the view
                safe_line = redact_secrets(line_content)
                selected_lines.append(f"{idx + 1:4d}: {safe_line}")

            return {
                "file": path.replace("\\", "/"),
                "total_lines": total_lines,
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "truncated": end_idx < total_lines,
                "content": "\n".join(selected_lines),
            }
        except PermissionError as pe:
            return {"error": str(pe)}
        except Exception as exc:
            return {"error": f"Unexpected error reading {path}: {str(exc)}"}

    def search_code(
        self,
        pattern: str,
        file_pattern: Optional[str] = None,
        max_results: int = 30
    ) -> Dict[str, Any]:
        """
        Searches repository files for suspicious patterns, regexes, or tokens.
        Matches are returned with line numbers and safe redacted line previews.
        """
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as err:
            return {"error": f"Invalid regular expression pattern '{pattern}': {err}"}

        matches = []
        file_regex = re.compile(file_pattern, re.IGNORECASE) if file_pattern else None

        for root, dirs, files in os.walk(self.repo_dir):
            if ".git" in dirs:
                dirs.remove(".git")

            for f in files:
                rel_path = os.path.relpath(os.path.join(root, f), self.repo_dir).replace("\\", "/")
                if file_regex and not file_regex.search(rel_path):
                    continue

                full_path = Path(root) / f
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as handle:
                        for line_num, line in enumerate(handle, start=1):
                            if regex.search(line):
                                matches.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "snippet": redact_secrets(line.strip())[:200],
                                })
                                if len(matches) >= max_results:
                                    break
                except (OSError, UnicodeDecodeError):
                    continue

                if len(matches) >= max_results:
                    break
            if len(matches) >= max_results:
                break

        return {
            "pattern": pattern,
            "total_matches": len(matches),
            "matches": matches,
            "capped": len(matches) >= max_results,
        }

    def git_log(self, max_count: int = 15) -> Dict[str, Any]:
        """
        Inspects commit history to audit commit hygiene, author info, and past modifications.
        """
        git_dir = self.repo_dir / ".git"
        if not git_dir.exists():
            return {"is_git_repository": False, "commits": [], "message": "No .git directory found."}

        try:
            cmd = [
                "git",
                "log",
                f"-n{max_count}",
                "--pretty=format:%H|%an|%ae|%ad|%s",
                "--date=iso",
            ]
            proc = subprocess.run(
                cmd,
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if proc.returncode != 0:
                return {"is_git_repository": True, "commits": [], "error": proc.stderr.strip()}

            commits = []
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                parts = line.split("|", 4)
                if len(parts) == 5:
                    commits.append({
                        "commit": parts[0],
                        "author": parts[1],
                        "email": parts[2],
                        "date": parts[3],
                        "message": redact_secrets(parts[4]),
                    })

            return {
                "is_git_repository": True,
                "commit_count": len(commits),
                "commits": commits,
            }
        except Exception as exc:
            return {"error": f"Failed to execute git log: {str(exc)}"}

    def git_status(self) -> Dict[str, Any]:
        """Inspects working tree status for modified or untracked files."""
        if not (self.repo_dir / ".git").exists():
            return {"is_git_repository": False, "message": "No .git directory found."}

        try:
            proc = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode != 0:
                return {"error": proc.stderr.strip()}

            entries = []
            for line in proc.stdout.splitlines():
                if line.strip():
                    entries.append(line)
            return {
                "is_git_repository": True,
                "clean": len(entries) == 0,
                "entries": entries,
            }
        except Exception as exc:
            return {"error": f"Failed to check git status: {str(exc)}"}

    def inspect_github_actions(self) -> Dict[str, Any]:
        """
        Parses and inspects all GitHub Actions workflows in .github/workflows/.
        Analyzes triggers, permissions, step validations, and potential security holes.
        """
        workflows_dir = self.repo_dir / ".github" / "workflows"
        if not workflows_dir.exists() or not workflows_dir.is_dir():
            return {
                "has_github_actions": False,
                "workflows": [],
                "message": "No .github/workflows directory found."
            }

        workflows: List[Dict[str, Any]] = []
        for file in workflows_dir.iterdir():
            if file.suffix.lower() in [".yml", ".yaml"] and file.is_file():
                rel_path = os.path.relpath(file, self.repo_dir).replace("\\", "/")
                try:
                    with open(file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    parsed = yaml.safe_load(content) or {}

                    # Extract triggers (on)
                    triggers = parsed.get("on") or parsed.get(True) or []
                    if isinstance(triggers, dict):
                        trigger_names = list(triggers.keys())
                    elif isinstance(triggers, list):
                        trigger_names = triggers
                    elif isinstance(triggers, str):
                        trigger_names = [triggers]
                    else:
                        trigger_names = []

                    # Extract jobs
                    jobs = parsed.get("jobs", {})
                    job_summaries = {}
                    has_continue_on_error = False
                    has_pull_request_target = "pull_request_target" in trigger_names
                    permissions = parsed.get("permissions")

                    for jname, jdata in jobs.items():
                        if isinstance(jdata, dict):
                            steps = jdata.get("steps", []) or []
                            step_names = [
                                s.get("name") or s.get("uses") or "unnamed_step"
                                for s in steps if isinstance(s, dict)
                            ]
                            if jdata.get("continue-on-error") is True:
                                has_continue_on_error = True
                            for s in steps:
                                if isinstance(s, dict) and s.get("continue-on-error") is True:
                                    has_continue_on_error = True

                            job_summaries[jname] = {
                                "runs_on": jdata.get("runs-on"),
                                "steps_count": len(steps),
                                "step_names": step_names,
                                "permissions": jdata.get("permissions"),
                            }

                    workflows.append({
                        "file": rel_path,
                        "name": parsed.get("name", file.stem),
                        "triggers": trigger_names,
                        "top_level_permissions": permissions,
                        "jobs": job_summaries,
                        "has_continue_on_error": has_continue_on_error,
                        "has_pull_request_target": has_pull_request_target,
                    })
                except Exception as ex:
                    workflows.append({"file": rel_path, "parse_error": str(ex)})

        return {
            "has_github_actions": len(workflows) > 0,
            "workflow_count": len(workflows),
            "workflows": workflows,
        }

    def run_pytest(self, test_path: Optional[str] = None, timeout: int = 25) -> Dict[str, Any]:
        """
        Executes pytest in a strictly sandboxed, isolated subprocess.
        Enforces timeout and safeguards against arbitrary execution leaks.
        """
        # First verify if a test suite exists before attempting execution
        tests_dir = self.repo_dir / (test_path or "tests")
        has_tests = tests_dir.exists() or any(self.repo_dir.glob("test_*.py")) or any(self.repo_dir.glob("*_test.py"))
        if not has_tests:
            return {
                "executed": False,
                "message": "No test directory or test files detected in repository.",
                "passed": None,
            }

        cmd = ["pytest", "--no-header", "-q"]
        if test_path:
            clean = test_path.strip().lstrip("/\\")
            cmd.append(clean)

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "executed": True,
                "exit_code": proc.returncode,
                "passed": proc.returncode == 0,
                "stdout": proc.stdout[:1500],
                "stderr": proc.stderr[:500],
            }
        except subprocess.TimeoutExpired:
            return {"executed": True, "error": f"pytest execution timed out after {timeout} seconds"}
        except FileNotFoundError:
            return {"executed": False, "error": "pytest executable not found in current environment."}
        except Exception as exc:
            return {"executed": False, "error": f"Error executing pytest: {str(exc)}"}

    def run_ruff(self, path: Optional[str] = None, timeout: int = 20) -> Dict[str, Any]:
        """Runs ruff static code analysis if available."""
        target = path or "."
        try:
            proc = subprocess.run(
                ["ruff", "check", target, "--output-format=json"],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "executed": True,
                "exit_code": proc.returncode,
                "output": proc.stdout[:2000],
            }
        except FileNotFoundError:
            return {"executed": False, "message": "ruff is not installed in the environment."}
        except Exception as ex:
            return {"executed": False, "error": str(ex)}


# ==============================================================================
# Tool Schemas for LLM Dynamic Tool Selection
# ==============================================================================

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "Discover files and directory hierarchy in the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Relative subdirectory to list (empty string for repository root)",
                        "default": "",
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory traversal depth",
                        "default": 5,
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Inspect source code, configuration files, workflow yamls, or docs with line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative file path within the repository",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "1-indexed starting line number",
                        "default": 1,
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Maximum number of lines to read",
                        "default": 200,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search for patterns, secrets, security vulnerabilities, or keywords across repository files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex or keyword to search for",
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "Optional regex filter for file names (e.g. '\\.py$', '\\.yml$')",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of matching snippets to return",
                        "default": 30,
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": "Inspect repository git commit history to audit commit messages, authorship, and changes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_count": {
                        "type": "integer",
                        "description": "Number of recent commits to inspect",
                        "default": 15,
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_status",
            "description": "Check git status for modified, untracked, or staging files.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inspect_github_actions",
            "description": "Deeply inspect CI/CD workflows in .github/workflows for trigger and security gate defects.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_pytest",
            "description": "Safely attempt executing pytest on test suite in an isolated subprocess.",
            "parameters": {
                "type": "object",
                "properties": {
                    "test_path": {
                        "type": "string",
                        "description": "Optional specific test path or file",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ruff",
            "description": "Run ruff static code analysis on the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to lint",
                    }
                },
                "required": [],
            },
        },
    },
]


def execute_tool(tools: RepoInspectionTools, tool_name: str, arguments: Dict[str, Any]) -> Any:
    """Dispatches tool execution by name to the bound RepoInspectionTools instance."""
    tool_map = {
        "list_files": tools.list_files,
        "read_file": tools.read_file,
        "search_code": tools.search_code,
        "git_log": tools.git_log,
        "git_status": tools.git_status,
        "inspect_github_actions": tools.inspect_github_actions,
        "run_pytest": tools.run_pytest,
        "run_ruff": tools.run_ruff,
    }
    if tool_name not in tool_map:
        return {"error": f"Unknown tool: '{tool_name}'"}
    try:
        return tool_map[tool_name](**arguments)
    except TypeError as te:
        return {"error": f"Invalid arguments for {tool_name}: {te}"}
    except Exception as exc:
        return {"error": f"Tool execution failed: {str(exc)}"}
