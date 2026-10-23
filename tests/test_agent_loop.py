import json
from pathlib import Path
import pytest

from agent_core.llm_client import OfflineMockClient
from agent_core.loop import DevOpsAgentLoop
from tools import RepoInspectionTools


def test_agent_loop_with_offline_engine(tmp_path):
    repo = tmp_path / "test_agent_repo"
    repo.mkdir()
    (repo / "README.md").write_text("# Test Repo\nShort readme", encoding="utf-8")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.env\n", encoding="utf-8")

    tools = RepoInspectionTools(repo)
    client = OfflineMockClient()

    agent = DevOpsAgentLoop(
        repository_url="https://github.com/test/repo",
        tools=tools,
        llm_client=client,
        max_steps=5,
    )
    report = agent.run()

    assert report.repository == "https://github.com/test/repo"
    assert isinstance(report.violations, list)
    # Check JSON validity
    json_output = report.to_json()
    parsed = json.loads(json_output)
    assert parsed["repository"] == "https://github.com/test/repo"
    assert "violations" in parsed
