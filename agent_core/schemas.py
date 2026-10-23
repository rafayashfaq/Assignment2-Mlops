"""
Data schemas and contracts for DevOps Repository Auditing Agent.
Strictly adheres to the assignment specification Section 5.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    """Allowed severity levels according to Assignment Specification Section 5."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DevOpsCategory(str, Enum):
    """Inspection categories according to Assignment Specification Section 4."""
    REPOSITORY_HYGIENE = "repository_hygiene"
    DEPENDENCY_MANAGEMENT = "dependency_management"
    CODE_QUALITY = "code_quality"
    TESTING = "testing"
    GITHUB_ACTIONS_CI = "github_actions_ci"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    COLLABORATION = "collaboration"
    BUILD_AND_RELEASE = "build_and_release"


# Patterns for redacting sensitive credentials to avoid reproducing secret values
SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token|password|auth|bearer|credential|access[_-]?key)[ \t]*[=:][ \t]*[\'"]([^\'"]{6,})[\'"]'),
    re.compile(r'(?i)(ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})'),
    re.compile(r'(?i)(sk-[a-zA-Z0-9_-]{20,}|gsk_[a-zA-Z0-9_-]{20,})'),
    re.compile(r'(?i)(AKIA[0-9A-Z]{16})'),
    re.compile(r'(?i)-----BEGIN [A-Z ]+ PRIVATE KEY-----'),
]


def redact_secrets(text: str) -> str:
    """Redacts any actual secret tokens, API keys, and credentials with ***REDACTED***."""
    if not text:
        return text
    
    redacted = text
    # Pattern 1: key = "value"
    def _sub_assignment(m):
        key_part = m.group(1)
        return f'{key_part} = "***REDACTED***"'
    redacted = re.sub(
        r'(?i)(api[_-]?key|secret|token|password|passwd|pwd|auth|credential|access[_-]?key)[ \t]*[=:][ \t]*[\'"][^\'"]+[\'"]',
        _sub_assignment,
        redacted
    )
    
    # Generic known prefixes
    redacted = re.sub(r'ghp_[a-zA-Z0-9]{20,}', 'ghp_***REDACTED***', redacted)
    redacted = re.sub(r'github_pat_[a-zA-Z0-9_]{20,}', 'github_pat_***REDACTED***', redacted)
    redacted = re.sub(r'sk-[a-zA-Z0-9_-]{20,}', 'sk-***REDACTED***', redacted)
    redacted = re.sub(r'gsk_[a-zA-Z0-9_-]{20,}', 'gsk_***REDACTED***', redacted)
    redacted = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', redacted)
    return redacted


class Violation(BaseModel):
    """
    Representation of an audited DevOps violation.
    All fields are required. file and line may be null when inapplicable.
    """
    rule_id: str = Field(..., description="Unique rule identifier (e.g. SEC-001, HYG-001)")
    category: str = Field(..., description="DevOps area category")
    severity: Severity = Field(..., description="Allowed severity: critical, high, medium, low")
    file: Optional[str] = Field(default=None, description="Relative file path where violation occurs, or null")
    line: Optional[int] = Field(default=None, description="1-indexed line number, or null")
    description: str = Field(..., description="Concise explanation of the defect")
    evidence: str = Field(..., description="Factual evidence discovered during inspection")
    recommendation: str = Field(..., description="Actionable remediation advice")

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Severity:
        if isinstance(v, Severity):
            return v
        s = str(v).strip().lower()
        if s not in [item.value for item in Severity]:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {list(Severity)}")
        return Severity(s)

    @field_validator("category", mode="before")
    @classmethod
    def normalize_category(cls, v: Any) -> str:
        s = str(v).strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")
        # Normalize common category synonyms
        if "hygiene" in s or "repo" in s:
            return DevOpsCategory.REPOSITORY_HYGIENE.value
        if "dep" in s or "package" in s:
            return DevOpsCategory.DEPENDENCY_MANAGEMENT.value
        if "quality" in s or "lint" in s or "code" in s:
            return DevOpsCategory.CODE_QUALITY.value
        if "test" in s:
            return DevOpsCategory.TESTING.value
        if "action" in s or "ci" in s or "cd" in s or "workflow" in s:
            return DevOpsCategory.GITHUB_ACTIONS_CI.value
        if "sec" in s:
            return DevOpsCategory.SECURITY.value
        if "config" in s or "env" in s:
            return DevOpsCategory.CONFIGURATION.value
        if "collab" in s or "pr" in s:
            return DevOpsCategory.COLLABORATION.value
        if "build" in s or "release" in s:
            return DevOpsCategory.BUILD_AND_RELEASE.value
        return s

    @model_validator(mode="after")
    def sanitize_evidence_and_description(self) -> Violation:
        # Never reproduce raw secrets in evidence or description
        self.evidence = redact_secrets(self.evidence)
        self.description = redact_secrets(self.description)
        return self


class AuditReport(BaseModel):
    """
    Top-level output contract required by Section 5 of assignment specification.
    """
    repository: str = Field(..., description="Target repository URL")
    violations: List[Violation] = Field(default_factory=list, description="Detected violations")

    def to_json(self, indent: int = 2) -> str:
        """Serializes report to exact required JSON schema."""
        return json.dumps(self.model_dump(mode="json"), indent=indent)


class ToolCallRecord(BaseModel):
    """Record of an executed tool call within the agent loop."""
    step: int
    tool_name: str
    arguments: Dict[str, Any]
    output_summary: str
    duration_ms: float = 0.0
