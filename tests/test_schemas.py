import json
import pytest
from agent_core.schemas import AuditReport, DevOpsCategory, Severity, Violation, redact_secrets


def test_redact_secrets_masks_keys():
    raw = "api_key = 'sk-proj-1234567890abcdef1234567890'"
    clean = redact_secrets(raw)
    assert "sk-proj" not in clean
    assert "***REDACTED***" in clean


def test_redact_secrets_masks_tokens():
    raw = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    clean = redact_secrets(raw)
    assert "ghp_abcdef" not in clean
    assert "ghp_***REDACTED***" in clean


def test_violation_model_normalization():
    v = Violation(
        rule_id="SEC-001",
        category="security",
        severity="CRITICAL",
        file="src/config.py",
        line=12,
        description="Hardcoded API token",
        evidence="AWS_SECRET_ACCESS_KEY = 'AKIA1234567890ABCDEF'",
        recommendation="Use AWS Secrets Manager or environment variables",
    )
    assert v.severity == Severity.CRITICAL
    assert v.category == "security"
    assert "AKIA" not in v.evidence
    assert "***REDACTED***" in v.evidence


def test_violation_null_file_and_line():
    v = Violation(
        rule_id="HYG-001",
        category="repository_hygiene",
        severity=Severity.MEDIUM,
        file=None,
        line=None,
        description="Missing README",
        evidence="No README found in repository",
        recommendation="Add README.md",
    )
    assert v.file is None
    assert v.line is None


def test_audit_report_json_serialization():
    v = Violation(
        rule_id="HYG-002",
        category="repository_hygiene",
        severity=Severity.HIGH,
        file=".gitignore",
        line=1,
        description="Missing .gitignore",
        evidence="File .gitignore does not exist",
        recommendation="Add standard .gitignore",
    )
    report = AuditReport(
        repository="https://github.com/example/demo-project",
        violations=[v],
    )
    json_str = report.to_json()
    data = json.loads(json_str)

    assert data["repository"] == "https://github.com/example/demo-project"
    assert len(data["violations"]) == 1
    assert data["violations"][0]["rule_id"] == "HYG-002"
    assert data["violations"][0]["severity"] == "high"
