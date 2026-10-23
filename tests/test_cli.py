import json
import subprocess
import sys
from pathlib import Path


def test_cli_execution_offline(tmp_path):
    # Setup dummy repo
    dummy_repo = tmp_path / "dummy_repo"
    dummy_repo.mkdir()
    (dummy_repo / "README.md").write_text("# Dummy Project\nDocumentation content.", encoding="utf-8")
    (dummy_repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n", encoding="utf-8")

    # Initialize a git repo so local cloner can inspect it
    subprocess.run(["git", "init"], cwd=str(dummy_repo), capture_output=True, check=True)

    out_file = tmp_path / "report.json"

    # Run agent.py via CLI
    cmd = [
        sys.executable,
        "agent.py",
        "--repo",
        str(dummy_repo),
        "--output",
        str(out_file),
        "--offline",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert res.returncode == 0, f"CLI exited with error: {res.stderr}"

    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "repository" in data
    assert "violations" in data
    assert isinstance(data["violations"], list)
