import os
import shutil
import tempfile
from pathlib import Path
import pytest

from tools import RepoInspectionTools, execute_tool


@pytest.fixture
def sample_repo(tmp_path):
    # Setup mock repository workspace
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()

    # Create README.md
    (repo_dir / "README.md").write_text("# Test Repo\nThis is a sample project for testing.", encoding="utf-8")

    # Create .gitignore
    (repo_dir / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n", encoding="utf-8")

    # Create src/
    src = repo_dir / "src"
    src.mkdir()
    (src / "app.py").write_text("import os\n\ndef run():\n    return 'OK'\n", encoding="utf-8")

    # Create .github/workflows
    wf_dir = repo_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_yaml = """
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Pytest
        run: pytest
"""
    (wf_dir / "ci.yml").write_text(wf_yaml, encoding="utf-8")

    return repo_dir


def test_list_files(sample_repo):
    tools = RepoInspectionTools(sample_repo)
    res = tools.list_files()
    assert "files" in res
    paths = [f["path"] for f in res["files"]]
    assert "README.md" in paths
    assert ".gitignore" in paths
    assert "src/app.py" in paths or "src\\app.py" in [p.replace("/", "\\") for p in paths]


def test_read_file(sample_repo):
    tools = RepoInspectionTools(sample_repo)
    res = tools.read_file("README.md")
    assert "content" in res
    assert "1: # Test Repo" in res["content"]
    assert res["total_lines"] == 2


def test_path_traversal_protection(sample_repo):
    tools = RepoInspectionTools(sample_repo)
    with pytest.raises(PermissionError):
        tools._safe_path("../../outside.txt")


def test_search_code(sample_repo):
    tools = RepoInspectionTools(sample_repo)
    res = tools.search_code("import os")
    assert res["total_matches"] >= 1
    assert any("app.py" in m["file"] for m in res["matches"])


def test_inspect_github_actions(sample_repo):
    tools = RepoInspectionTools(sample_repo)
    res = tools.inspect_github_actions()
    assert res["has_github_actions"] is True
    assert res["workflow_count"] == 1
    wf = res["workflows"][0]
    assert "push" in wf["triggers"]
    assert "pull_request" in wf["triggers"]


def test_execute_tool_dispatch(sample_repo):
    tools = RepoInspectionTools(sample_repo)
    res = execute_tool(tools, "read_file", {"path": "README.md", "start_line": 1, "max_lines": 5})
    assert "content" in res
    assert "Test Repo" in res["content"]
