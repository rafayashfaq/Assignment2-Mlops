from pathlib import Path
import pytest

from agent_core.rules import DeterministicAuditor
from tools import RepoInspectionTools


def test_auditor_detects_missing_readme(tmp_path):
    repo = tmp_path / "repo_no_readme"
    repo.mkdir()
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n", encoding="utf-8")

    tools = RepoInspectionTools(repo)
    auditor = DeterministicAuditor(tools)
    violations = auditor.audit_all()

    rule_ids = [v.rule_id for v in violations]
    assert "HYG-001" in rule_ids


def test_auditor_detects_unsuitable_gitignore(tmp_path):
    repo = tmp_path / "repo_bad_gitignore"
    repo.mkdir()
    (repo / "README.md").write_text("# Documentation\nGood docs here.", encoding="utf-8")
    (repo / ".gitignore").write_text("random_file.txt\n", encoding="utf-8")

    tools = RepoInspectionTools(repo)
    auditor = DeterministicAuditor(tools)
    violations = auditor.audit_all()

    rule_ids = [v.rule_id for v in violations]
    assert "HYG-002" in rule_ids


def test_auditor_detects_committed_env(tmp_path):
    repo = tmp_path / "repo_committed_env"
    repo.mkdir()
    (repo / "README.md").write_text("# Project\nValid project docs.", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n", encoding="utf-8")
    (repo / ".env").write_text("SECRET_KEY=supersecret123456\n", encoding="utf-8")

    tools = RepoInspectionTools(repo)
    auditor = DeterministicAuditor(tools)
    violations = auditor.audit_all()

    rule_ids = [v.rule_id for v in violations]
    assert "CFG-002" in rule_ids


def test_auditor_detects_ci_continue_on_error(tmp_path):
    repo = tmp_path / "repo_ci_flaw"
    repo.mkdir()
    (repo / "README.md").write_text("# Project with CI flaws\nDescription.", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n", encoding="utf-8")

    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_content = """
name: BadCI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
      - run: pytest
"""
    (wf_dir / "test.yml").write_text(wf_content, encoding="utf-8")

    tools = RepoInspectionTools(repo)
    auditor = DeterministicAuditor(tools)
    violations = auditor.audit_all()

    rule_ids = [v.rule_id for v in violations]
    assert "CI-001" in rule_ids  # continue-on-error
    assert "CI-003" in rule_ids  # missing pull_request trigger
