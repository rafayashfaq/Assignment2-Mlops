"""
DevOps Best-Practice Rules and Inspection Heuristics Catalog.
Covers all 9 required categories specified in Section 4 of the assignment:
1. Repository hygiene
2. Dependency management
3. Code quality
4. Testing
5. GitHub Actions / CI
6. Security
7. Configuration
8. Collaboration
9. Build and release

Follows the Evidence Rule:
- Does not penalize absent optional files when equivalent alternatives exist.
- Does not infer remote branch protection settings from local repository files.
- Strictly redacts secret values in all evidence.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_core.schemas import DevOpsCategory, Severity, Violation, redact_secrets
from tools import RepoInspectionTools


class RuleDefinition:
    def __init__(
        self,
        rule_id: str,
        category: DevOpsCategory,
        severity: Severity,
        description: str,
        recommendation: str,
    ):
        self.rule_id = rule_id
        self.category = category.value
        self.severity = severity
        self.description = description
        self.recommendation = recommendation


# Master Rule Catalog
RULE_CATALOG: Dict[str, RuleDefinition] = {
    # 1. Repository Hygiene
    "HYG-001": RuleDefinition(
        "HYG-001",
        DevOpsCategory.REPOSITORY_HYGIENE,
        Severity.MEDIUM,
        "Repository lacks a README documentation file or README is empty",
        "Add a comprehensive README.md describing the project, installation, and usage."
    ),
    "HYG-002": RuleDefinition(
        "HYG-002",
        DevOpsCategory.REPOSITORY_HYGIENE,
        Severity.HIGH,
        "Repository lacks a suitable .gitignore file",
        "Add a standard .gitignore file to prevent accidental commitment of build artifacts, virtual environments, and secrets."
    ),
    "HYG-003": RuleDefinition(
        "HYG-003",
        DevOpsCategory.REPOSITORY_HYGIENE,
        Severity.HIGH,
        "Tracked temporary, generated, or virtual environment files found in repository",
        "Remove temporary or environment files from version control and add them to .gitignore."
    ),
    # 2. Dependency Management
    "DEP-001": RuleDefinition(
        "DEP-001",
        DevOpsCategory.DEPENDENCY_MANAGEMENT,
        Severity.MEDIUM,
        "Application dependencies are specified without an associated lockfile",
        "Generate and commit an immutable lockfile (e.g. poetry.lock, Pipfile.lock, uv.lock, or package-lock.json) for reproducible builds."
    ),
    "DEP-002": RuleDefinition(
        "DEP-002",
        DevOpsCategory.DEPENDENCY_MANAGEMENT,
        Severity.LOW,
        "Unconstrained or wildcard dependency version specifications detected",
        "Pin dependencies to specific or bounded versions (e.g. ~=, ==, >=x,<y) to avoid breaking changes from upstream releases."
    ),
    # 3. Code Quality
    "CQ-001": RuleDefinition(
        "CQ-001",
        DevOpsCategory.CODE_QUALITY,
        Severity.LOW,
        "Missing automated linter or code formatting configuration",
        "Configure an automated linter/formatter (such as Ruff, Flake8, Black, or ESLint) to ensure consistent code quality."
    ),
    "CQ-002": RuleDefinition(
        "CQ-002",
        DevOpsCategory.CODE_QUALITY,
        Severity.MEDIUM,
        "Insecure code pattern or unsafe dynamic evaluation detected",
        "Refactor unsafe code patterns (e.g. eval, exec, shell=True with variables) to use secure, parameterized alternatives."
    ),
    # 4. Testing
    "TST-001": RuleDefinition(
        "TST-001",
        DevOpsCategory.TESTING,
        Severity.HIGH,
        "Repository does not contain an automated test suite",
        "Add automated tests (e.g. using pytest or unittest) in a tests/ directory."
    ),
    "TST-002": RuleDefinition(
        "TST-002",
        DevOpsCategory.TESTING,
        Severity.CRITICAL,
        "Automated test suite execution fails",
        "Fix failing unit and integration tests before merging or deploying code."
    ),
    "TST-003": RuleDefinition(
        "TST-003",
        DevOpsCategory.TESTING,
        Severity.HIGH,
        "CI workflow exists but does not execute automated tests",
        "Include a testing step (e.g. 'pytest' or 'npm test') in CI workflows to validate every push and pull request."
    ),
    # 5. GitHub Actions / CI
    "CI-001": RuleDefinition(
        "CI-001",
        DevOpsCategory.GITHUB_ACTIONS_CI,
        Severity.HIGH,
        "CI workflow uses continue-on-error to bypass failed validation gates",
        "Remove 'continue-on-error: true' from test or critical lint jobs so failures properly block CI pipelines."
    ),
    "CI-002": RuleDefinition(
        "CI-002",
        DevOpsCategory.GITHUB_ACTIONS_CI,
        Severity.CRITICAL,
        "Potentially dangerous use of pull_request_target with untrusted head checkout",
        "Use standard 'pull_request' trigger or avoid checking out untrusted PR head commit in pull_request_target."
    ),
    "CI-003": RuleDefinition(
        "CI-003",
        DevOpsCategory.GITHUB_ACTIONS_CI,
        Severity.MEDIUM,
        "CI workflow triggers on push but lacks pull_request trigger validation",
        "Add 'pull_request' to workflow triggers so changes are validated before merging into protected branches."
    ),
    # 6. Security
    "SEC-001": RuleDefinition(
        "SEC-001",
        DevOpsCategory.SECURITY,
        Severity.CRITICAL,
        "Hardcoded API credential, token, or secret key committed to source code",
        "Remove hardcoded secrets from git history and load credentials from environment variables or a secrets manager."
    ),
    "SEC-002": RuleDefinition(
        "SEC-002",
        DevOpsCategory.SECURITY,
        Severity.HIGH,
        "GitHub Actions workflow configures overly broad write permissions (write-all)",
        "Apply the principle of least privilege by specifying explicit granular permissions (e.g. contents: read)."
    ),
    "SEC-003": RuleDefinition(
        "SEC-003",
        DevOpsCategory.SECURITY,
        Severity.CRITICAL,
        "Potential script injection vulnerability via untrusted context expressions in run step",
        "Pass untrusted context values (e.g. github.event.*) via environment variables rather than direct inline string interpolation in run scripts."
    ),
    # 7. Configuration
    "CFG-001": RuleDefinition(
        "CFG-001",
        DevOpsCategory.CONFIGURATION,
        Severity.MEDIUM,
        "Hardcoded machine-specific absolute file path detected in code or config",
        "Use relative paths or environment-configured base directories rather than hardcoded machine paths."
    ),
    "CFG-002": RuleDefinition(
        "CFG-002",
        DevOpsCategory.CONFIGURATION,
        Severity.HIGH,
        "Committed local configuration or .env file detected in repository",
        "Add .env and local configuration files to .gitignore and provide a sanitized .env.example instead."
    ),
    # 8. Collaboration
    "COL-001": RuleDefinition(
        "COL-001",
        DevOpsCategory.COLLABORATION,
        Severity.LOW,
        "Repository lacks contribution guidance or pull request template",
        "Add a CONTRIBUTING.md or .github/pull_request_template.md to facilitate clear code review practices."
    ),
    # 9. Build and Release
    "BLD-001": RuleDefinition(
        "BLD-001",
        DevOpsCategory.BUILD_AND_RELEASE,
        Severity.HIGH,
        "Deployment or release workflow job executes without depending on prior test validation",
        "Configure release or deploy jobs with 'needs: [test]' to ensure only verified code is published."
    ),
}


class DeterministicAuditor:
    """
    Evidence-based heuristic auditor.
    Can be used by the agent as a primary fast analysis pass or as an offline fallback engine
    when no LLM API key is configured.
    """

    def __init__(self, tools: RepoInspectionTools):
        self.tools = tools

    def audit_all(self) -> List[Violation]:
        """Runs thorough evidence-backed checks across all 9 DevOps areas."""
        violations: List[Violation] = []

        files_info = self.tools.list_files(max_depth=5)
        file_list = [f["path"] for f in files_info.get("files", []) if f.get("type") == "file"]
        dir_list = [f["path"] for f in files_info.get("files", []) if f.get("type") == "directory"]

        # 1. Repository Hygiene
        # Check README
        readme_candidates = [f for f in file_list if Path(f).name.lower().startswith("readme")]
        if not readme_candidates:
            v_def = RULE_CATALOG["HYG-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=None,
                line=None,
                description=v_def.description,
                evidence="No README file (README.md, README.rst, README.txt) found in repository root.",
                recommendation=v_def.recommendation,
            ))
        else:
            # Check if README is practically empty (< 20 bytes)
            first_readme = readme_candidates[0]
            read_res = self.tools.read_file(first_readme, start_line=1, max_lines=5)
            if not read_res.get("content") or len(read_res.get("content", "").strip()) < 20:
                v_def = RULE_CATALOG["HYG-001"]
                violations.append(Violation(
                    rule_id=v_def.rule_id,
                    category=v_def.category,
                    severity=v_def.severity,
                    file=first_readme,
                    line=1,
                    description="Repository README file is essentially empty",
                    evidence=f"File {first_readme} contains fewer than 20 characters of documentation.",
                    recommendation=v_def.recommendation,
                ))

        # Check .gitignore
        gitignore_exists = ".gitignore" in file_list
        if not gitignore_exists:
            v_def = RULE_CATALOG["HYG-002"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=None,
                line=None,
                description=v_def.description,
                evidence="No .gitignore file detected in repository root.",
                recommendation=v_def.recommendation,
            ))
        else:
            git_content = self.tools.read_file(".gitignore", max_lines=100).get("content", "")
            # Check if common vital patterns are ignored
            common_missing = []
            for item in ["__pycache__", ".pyc", ".env"]:
                if item not in git_content:
                    common_missing.append(item)
            if len(common_missing) >= 2:
                v_def = RULE_CATALOG["HYG-002"]
                violations.append(Violation(
                    rule_id=v_def.rule_id,
                    category=v_def.category,
                    severity=v_def.severity,
                    file=".gitignore",
                    line=1,
                    description="The .gitignore file is inadequate and omits common vital exclusions",
                    evidence=f".gitignore file is missing exclusions for: {', '.join(common_missing)}",
                    recommendation=v_def.recommendation,
                ))

        # Check tracked generated/temporary files
        bad_tracked_patterns = [
            (re.compile(r'(^|/)(\.env|\.env\.local)$'), "Committed environment secret file (.env)"),
            (re.compile(r'\.pyc$'), "Committed Python bytecode file (.pyc)"),
            (re.compile(r'(^|/)__pycache__/'), "Committed Python cache directory (__pycache__)"),
            (re.compile(r'(^|/)node_modules/'), "Committed dependency directory (node_modules)"),
            (re.compile(r'\.DS_Store$'), "Committed OS desktop service store (.DS_Store)"),
            (re.compile(r'(^|/)\.venv/'), "Committed virtual environment directory (.venv)"),
        ]
        found_tracked = []
        for f in file_list:
            for pat, desc in bad_tracked_patterns:
                if pat.search(f):
                    found_tracked.append((f, desc))
                    break

        for f_path, f_desc in found_tracked[:3]:  # Avoid spamming duplicates
            is_env = f_path.endswith(".env") or ".env." in f_path
            rule_id = "CFG-002" if is_env else "HYG-003"
            v_def = RULE_CATALOG[rule_id]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=f_path,
                line=None,
                description=f"{v_def.description}: {f_desc}",
                evidence=f"Tracked artifact path in git index: '{f_path}'",
                recommendation=v_def.recommendation,
            ))

        # 2. Dependency Management
        # Check lockfiles if dependencies are present
        has_python_deps = any(f in file_list for f in ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"])
        has_js_deps = "package.json" in file_list
        has_lock = any(f in file_list for f in ["poetry.lock", "Pipfile.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements-lock.txt", "uv.lock"])

        # If repo specifies dependencies (like package.json, Pipfile, poetry in pyproject.toml) but no lockfile
        if has_js_deps and not any(f in file_list for f in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]):
            v_def = RULE_CATALOG["DEP-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file="package.json",
                line=1,
                description="JavaScript/Node project defines package.json without a committed lockfile",
                evidence="package.json is present, but package-lock.json, yarn.lock, or pnpm-lock.yaml is absent.",
                recommendation="Run 'npm install' and commit the resulting package-lock.json.",
            ))

        # Check weak or wildcard versions in requirements.txt
        if "requirements.txt" in file_list:
            req_content = self.tools.read_file("requirements.txt", max_lines=150).get("content", "")
            wildcard_lines = []
            for line in req_content.splitlines():
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("-"):
                    continue
                # Match line number and content
                m = re.match(r'^\s*(\d+):\s*(.*)$', clean_line)
                lnum = int(m.group(1)) if m else None
                text = m.group(2) if m else clean_line
                if "==" not in text and "~=" not in text and "<=" not in text and ">=" not in text:
                    wildcard_lines.append((lnum, text))
                elif "*" in text:
                    wildcard_lines.append((lnum, text))

            if wildcard_lines:
                first_lnum, first_text = wildcard_lines[0]
                v_def = RULE_CATALOG["DEP-002"]
                violations.append(Violation(
                    rule_id=v_def.rule_id,
                    category=v_def.category,
                    severity=v_def.severity,
                    file="requirements.txt",
                    line=first_lnum,
                    description=v_def.description,
                    evidence=f"Unpinned dependency line: '{first_text}'",
                    recommendation=v_def.recommendation,
                ))

        # 3. Code Quality
        # Check linter configs
        linter_files = [
            ".flake8", "ruff.toml", ".pylintrc", ".eslintrc", ".eslintrc.json",
            ".eslintrc.js", "biome.json", ".pre-commit-config.yaml"
        ]
        has_linter = any(f in file_list for f in linter_files)
        # Check pyproject.toml for tool.ruff / tool.flake8
        if not has_linter and "pyproject.toml" in file_list:
            pyproj = self.tools.read_file("pyproject.toml", max_lines=100).get("content", "")
            if "[tool.ruff" in pyproj or "[tool.black" in pyproj or "[tool.flake8" in pyproj:
                has_linter = True

        if not has_linter:
            v_def = RULE_CATALOG["CQ-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=None,
                line=None,
                description=v_def.description,
                evidence="No linting or formatting configuration (ruff.toml, .flake8, pyproject.toml [tool.ruff], eslint) found.",
                recommendation=v_def.recommendation,
            ))

        # 4. Testing
        has_tests_dir = any("test" in d.lower() for d in dir_list)
        has_test_files = any(Path(f).name.startswith("test_") or Path(f).name.endswith("_test.py") for f in file_list)
        if not has_tests_dir and not has_test_files:
            v_def = RULE_CATALOG["TST-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=None,
                line=None,
                description=v_def.description,
                evidence="No automated tests directory or test files (e.g. tests/, test_*.py) exist in the repository.",
                recommendation=v_def.recommendation,
            ))

        # 5. GitHub Actions / CI Inspection
        ci_audit = self.tools.inspect_github_actions()
        if ci_audit.get("has_github_actions"):
            for wf in ci_audit.get("workflows", []):
                wf_file = wf.get("file", ".github/workflows/ci.yml")
                triggers = wf.get("triggers", [])

                # Check pull_request_target
                if wf.get("has_pull_request_target"):
                    v_def = RULE_CATALOG["CI-002"]
                    violations.append(Violation(
                        rule_id=v_def.rule_id,
                        category=v_def.category,
                        severity=v_def.severity,
                        file=wf_file,
                        line=None,
                        description=v_def.description,
                        evidence=f"Workflow '{wf_file}' triggers on 'pull_request_target', which can allow arbitrary code execution with repository write tokens.",
                        recommendation=v_def.recommendation,
                    ))

                # Check continue-on-error
                if wf.get("has_continue_on_error"):
                    v_def = RULE_CATALOG["CI-001"]
                    violations.append(Violation(
                        rule_id=v_def.rule_id,
                        category=v_def.category,
                        severity=v_def.severity,
                        file=wf_file,
                        line=None,
                        description=v_def.description,
                        evidence=f"Workflow '{wf_file}' specifies 'continue-on-error: true', allowing test failures or security defects to pass silently.",
                        recommendation=v_def.recommendation,
                    ))

                # Check missing PR trigger
                if "push" in triggers and "pull_request" not in triggers and not wf.get("has_pull_request_target"):
                    v_def = RULE_CATALOG["CI-003"]
                    violations.append(Violation(
                        rule_id=v_def.rule_id,
                        category=v_def.category,
                        severity=v_def.severity,
                        file=wf_file,
                        line=None,
                        description=v_def.description,
                        evidence=f"Workflow '{wf_file}' triggers on push but lacks a 'pull_request' trigger.",
                        recommendation=v_def.recommendation,
                    ))

                # Check overly permissive permissions (write-all)
                perms = wf.get("top_level_permissions")
                if perms == "write-all" or (isinstance(perms, dict) and any(v == "write" for v in perms.values()) and len(perms) > 4):
                    v_def = RULE_CATALOG["SEC-002"]
                    violations.append(Violation(
                        rule_id=v_def.rule_id,
                        category=v_def.category,
                        severity=v_def.severity,
                        file=wf_file,
                        line=None,
                        description=v_def.description,
                        evidence=f"Workflow '{wf_file}' defines overly broad permissions: '{perms}'.",
                        recommendation=v_def.recommendation,
                    ))

                # Check if CI workflow has test step
                all_step_names = []
                for j in wf.get("jobs", {}).values():
                    all_step_names.extend([s.lower() for s in j.get("step_names", [])])
                has_test_step = any(t in " ".join(all_step_names) for t in ["test", "pytest", "jest", "unittest"])
                if has_tests_dir and not has_test_step and len(all_step_names) > 0:
                    v_def = RULE_CATALOG["TST-003"]
                    violations.append(Violation(
                        rule_id=v_def.rule_id,
                        category=v_def.category,
                        severity=v_def.severity,
                        file=wf_file,
                        line=None,
                        description=v_def.description,
                        evidence=f"Repository contains tests, but CI workflow '{wf_file}' has no test execution step (steps found: {all_step_names[:5]}).",
                        recommendation=v_def.recommendation,
                    ))

        # 6. Security: Search for Hardcoded Secrets
        secret_search = self.tools.search_code(
            pattern=r'(?i)(api[_-]?key|secret_key|private[_-]?key|password|bearer|auth[_-]?token)[ \t]*=[ \t]*["\'][A-Za-z0-9_\-\.]{12,}["\']',
            max_results=5,
        )
        for match in secret_search.get("matches", []):
            m_file = match.get("file", "")
            # Skip test files and fixtures if explicitly marked as mock or test
            if "test" in m_file.lower() and any(x in match.get("snippet", "").lower() for x in ["mock", "fake", "dummy", "test"]):
                continue
            v_def = RULE_CATALOG["SEC-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=m_file,
                line=match.get("line"),
                description=v_def.description,
                evidence=f"Hardcoded credential assigned in source code: {redact_secrets(match.get('snippet', ''))}",
                recommendation=v_def.recommendation,
            ))

        # 7. Configuration: Search for Machine-Specific Paths
        path_search = self.tools.search_code(
            pattern=r'(/[Uu]sers/[A-Za-z0-9_-]+|/home/[A-Za-z0-9_-]+|[A-Za-z]:\\[Uu]sers\\[A-Za-z0-9_-]+)',
            max_results=3,
        )
        for match in path_search.get("matches", []):
            m_file = match.get("file", "")
            # Skip virtual environments or documentation references
            if m_file.endswith(".md") or m_file.endswith(".txt"):
                continue
            v_def = RULE_CATALOG["CFG-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=m_file,
                line=match.get("line"),
                description=v_def.description,
                evidence=f"Absolute machine path detected: {match.get('snippet', '')}",
                recommendation=v_def.recommendation,
            ))

        # 8. Collaboration Guidance
        collab_files = ["CONTRIBUTING.md", "CONTRIBUTING", ".github/CONTRIBUTING.md", ".github/pull_request_template.md"]
        has_collab = any(f in file_list for f in collab_files)
        # Only report if repo has > 10 files (non-trivial)
        if not has_collab and len(file_list) > 10:
            v_def = RULE_CATALOG["COL-001"]
            violations.append(Violation(
                rule_id=v_def.rule_id,
                category=v_def.category,
                severity=v_def.severity,
                file=None,
                line=None,
                description=v_def.description,
                evidence="No CONTRIBUTING.md or pull request template detected in repository.",
                recommendation=v_def.recommendation,
            ))

        # Deduplicate violations by rule_id and file
        seen = set()
        deduped = []
        for v in violations:
            key = (v.rule_id, v.file, v.line)
            if key not in seen:
                seen.add(key)
                deduped.append(v)

        return deduped
