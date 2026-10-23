"""
Git repository workspace and cloner module.
Safely clones public GitHub repositories into isolated temporary workspaces
and guarantees full cleanup so the inspected repository is left completely unchanged.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


GITHUB_URL_REGEX = re.compile(
    r"^(https?://)?(www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$"
)


class ClonerError(Exception):
    """Raised when repository cloning or isolation fails."""
    pass


class RepoWorkspace:
    """
    Context manager that prepares and manages an isolated workspace for repository audit.
    Guarantees cleanup on exit so that target repositories remain strictly untouched.
    """

    def __init__(self, repo_target: str, custom_temp_dir: Optional[str] = None):
        self.repo_target = repo_target.strip()
        self.custom_temp_dir = custom_temp_dir
        self.workspace_path: Optional[Path] = None
        self._is_temp = False

    def __enter__(self) -> Path:
        self.workspace_path = self._prepare_workspace()
        return self.workspace_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def _prepare_workspace(self) -> Path:
        """Determines if target is local or remote and prepares isolated directory."""
        # 1. Check if target is a local directory (useful for tests and offline audits)
        local_path = Path(self.repo_target).resolve()
        if local_path.is_dir() and (local_path / ".git").exists():
            temp_dir = tempfile.mkdtemp(prefix="audit_local_", dir=self.custom_temp_dir)
            self._is_temp = True
            # Clone local repo to isolate completely
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", f"file:///{local_path.as_posix()}", temp_dir],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=60,
                )
                return Path(temp_dir)
            except Exception as e:
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise ClonerError(f"Failed to clone local repository: {e}")

        # 2. Remote repository URL handling
        url = self.repo_target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        # Normalize git url
        clean_url = url.rstrip("/")
        if not clean_url.endswith(".git"):
            clone_url = f"{clean_url}.git"
        else:
            clone_url = clean_url

        temp_dir = tempfile.mkdtemp(prefix="devops_audit_", dir=self.custom_temp_dir)
        self._is_temp = True

        try:
            # Clone with depth 50 to capture history for git_log without excessive download time
            cmd = [
                "git",
                "clone",
                "--depth",
                "50",
                clone_url,
                temp_dir,
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                # If shallow clone failed or branch issue, try normal clone
                err_msg = result.stderr.strip()
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise ClonerError(
                    f"Git clone failed for repository '{self.repo_target}'. Exit code: {result.returncode}. Details: {err_msg}"
                )

            return Path(temp_dir)
        except subprocess.TimeoutExpired:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ClonerError(f"Cloning timed out after 120 seconds for repository: {self.repo_target}")
        except ClonerError:
            raise
        except Exception as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ClonerError(f"Unexpected error while preparing repository workspace: {exc}")

    def cleanup(self) -> None:
        """Removes the temporary directory and all extracted files."""
        if self._is_temp and self.workspace_path and self.workspace_path.exists():
            # Handle Windows read-only git files during deletion
            def _remove_readonly(func, path, exc_info):
                try:
                    os.chmod(path, 0o777)
                    func(path)
                except Exception:
                    pass

            shutil.rmtree(str(self.workspace_path), onerror=_remove_readonly, ignore_errors=True)
