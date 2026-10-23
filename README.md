# Autonomous AI Agent for DevOps Repository Auditing

[![CI](https://github.com/rafayashfaq/Assignment2-Mlops/actions/workflows/ci.yml/badge.svg)](https://github.com/rafayashfaq/Assignment2-Mlops/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Testing: pytest](https://img.shields.io/badge/testing-pytest-blue.svg)](https://docs.pytest.org/)

An autonomous AI agent designed to inspect public GitHub repositories, detect DevOps best-practice violations, and produce actionable, evidence-based reports without human intervention.

Developed for **Assignment 2: MLOps & Production AI Engineering**.

---

## 1. Architectural Highlights

- **Pure Python Control Loop**: Strictly compliant with course framework restrictions—**zero** LangChain, LangGraph, n8n, or prebuilt orchestration frameworks. All agent reasoning, tool dispatching, and control flows are implemented natively.
- **100% Free Gemini API Integration**: Pre-configured for **Google Gemini Free Tier** (`gemini-1.5-flash` & `gemini-2.0-flash`) via Google AI Studio, offering **1,500 free requests per day**, **15 requests/minute**, and **1,000,000 tokens/minute** at **$0 fee** with no credit card required. Also supports Groq Cloud, OpenRouter Free models, and an offline deterministic fallback engine.
- **Strict Evidence Rules**:
  - *No False Equivalence Penalties*: Modern alternatives (e.g. `pyproject.toml` instead of `requirements.txt`, `poetry.lock` instead of `package-lock.json`) are respected and not treated as defects.
  - *No Remote Branch Protection Inference*: Never invents or assumes remote GitHub settings from local files.
  - *Guaranteed Secret Redaction*: Every secret, credential, or API key identified is automatically masked as `***REDACTED***` in evidence and descriptions.
  - *Isolated Non-Destructive Auditing*: Repositories are cloned into ephemeral sandboxes and destroyed upon completion, leaving inspected code untouched.

---

## 2. Agent Workflow Cycle

The agent operates in an autonomous cycle:

```
┌─────────────────────────────────────────────────────────────┐
│                      Target Repository                      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
 1. OBSERVE   ◄─── Discovers file tree, workflows, configs, git
      │
      ▼
 2. REASON    ◄─── LLM analyzes observations against DevOps catalog
      │
      ▼
 3. SELECT    ◄─── Dynamic tool choice (read_file, search_code, etc.)
      │
      ▼
 4. EXECUTE   ◄─── Sandboxed Python tool execution & path bounds
      │
      ▼
 5. INTERPRET ◄─── Formats results, extracts evidence, redacts secrets
      │
      ▼
 6. REPORT    ◄─── Produces validated machine-readable JSON output
```

---

## 3. Supported Inspection Tools

All inspection tools are implemented in `tools.py` with path traversal protection and safety isolation:

| Tool | Purpose | Status |
| :--- | :--- | :--- |
| `list_files(directory, max_depth)` | Discovers files and folder structure while filtering `.git` internals | **Required** |
| `read_file(path, start_line, max_lines)` | Safely views file contents with 1-indexed numbering and secret masking | **Required** |
| `search_code(pattern, file_pattern)` | Regex-based search across repository for patterns, credentials, or paths | **Required** |
| `git_log(max_count)` | Audits commit history, authorship, and commit message hygiene | **Required** |
| `git_status()` | Checks working directory status and untracked files | Optional |
| `inspect_github_actions()` | Deep analysis of `.github/workflows` for triggers, gates, and permissions | Optional |
| `run_pytest(test_path)` | Executes pytest in a sandboxed, timed-out subprocess | Optional |
| `run_ruff(path)` | Performs static code and formatting analysis | Optional |

---

## 4. DevOps Inspection Areas

The agent inspects target repositories across all 9 areas defined in the specification:

| Category | Identifier | Description | Default Severity |
| :--- | :--- | :--- | :--- |
| **Repository Hygiene** | `HYG-001` | Missing or empty README documentation | `medium` |
| | `HYG-002` | Inadequate or missing `.gitignore` file | `high` |
| | `HYG-003` | Tracked build artifacts, caches, or virtual environments | `high` |
| **Dependency Management** | `DEP-001` | Missing lockfile for declared dependencies | `medium` |
| | `DEP-002` | Unconstrained or wildcard dependency versions | `low` |
| **Code Quality** | `CQ-001` | Missing automated linter/formatter configuration | `low` |
| | `CQ-002` | Insecure code patterns or unsafe dynamic evaluation | `medium` |
| **Testing** | `TST-001` | Repository does not contain an automated test suite | `high` |
| | `TST-002` | Automated test suite execution fails | `critical` |
| | `TST-003` | CI workflow exists but does not execute tests | `high` |
| **GitHub Actions / CI** | `CI-001` | Ineffective gates via `continue-on-error: true` | `high` |
| | `CI-002` | Dangerous `pull_request_target` with untrusted checkout | `critical` |
| | `CI-003` | Push trigger without pull request validation trigger | `medium` |
| **Security** | `SEC-001` | Hardcoded API keys, tokens, or credentials | `critical` |
| | `SEC-002` | Overly broad workflow permissions (`write-all`) | `high` |
| | `SEC-003` | Script injection via untrusted context expressions | `critical` |
| **Configuration** | `CFG-001` | Hardcoded machine-specific absolute paths (`/home/...`) | `medium` |
| | `CFG-002` | Committed local `.env` configuration file | `high` |
| **Collaboration** | `COL-001` | Missing contribution guide or PR template | `low` |
| **Build & Release** | `BLD-001` | Deployment job without preceding test dependencies | `high` |

---

## 5. Free API Setup Guide

This agent is built to operate with **100% free AI APIs** with zero financial cost:

### Option A: Google Gemini Free API (Recommended Default — 100% Free)
1. Visit [Google AI Studio](https://aistudio.google.com/) and sign in with your Google account.
2. Click **Get API key** and generate a free API key (no credit card or billing required).
3. Configure your local `.env`:
   ```bash
   cp .env.example .env
   # Add your free Gemini key to .env:
   GEMINI_API_KEY=AIzaSy...
   ```
4. Free tier quotas:
   - **1,500 requests / day**
   - **15 requests / minute**
   - **1,000,000 tokens / minute**
   - Models: `gemini-1.5-flash` (fast & lightweight) or `gemini-2.0-flash`

### Option B: Groq Cloud Free Tier (Alternative — 14,400 Requests/Day)
1. Obtain an API key from [Groq Console](https://console.groq.com/keys) (no credit card required).
2. Add `GROQ_API_KEY=gsk_...` to `.env`.

### Option C: Offline / Mock Mode (Zero Network, Unlimited Runs)
- Run with the `--offline` flag to execute using the built-in deterministic heuristic engine. No API key or internet access required. Ideal for automated CI testing and grading.

---

## 6. Installation & Execution

### Prerequisites
- Python 3.10 or higher
- Git installed on your system

### Installation
```bash
# 1. Clone this repository
git clone https://github.com/rafayashfaq/Assignment2-Mlops.git
cd Assignment2-Mlops

# 2. Create and activate a virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Execution Interface
Run unattended audits using the standard assignment interface:

```bash
# Standard command
python agent.py --repo https://github.com/example/demo-project --output report.json

# Offline evaluation (for automated testing or grading environments without API keys)
python agent.py --repo https://github.com/example/demo-project --output report.json --offline

# Verbose logging mode
python agent.py --repo https://github.com/example/demo-project --output report.json -v
```

---

## 7. Output Contract

The agent generates a machine-readable JSON document conforming strictly to Section 5:

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential, token, or secret key committed to source code",
      "evidence": "Hardcoded credential assigned in source code: API_KEY = \"***REDACTED***\"",
      "recommendation": "Remove hardcoded secrets from git history and load credentials from environment variables or a secrets manager."
    }
  ]
}
```

---

## 8. Automated Testing

Run the automated test suite with `pytest`:

```bash
pytest tests/ -v
```

All 17 automated unit and integration tests validate tool isolation, directory traversal prevention, secret masking, schema serialization, agent loop execution, and CLI behavior.

---

## 9. Project Structure

```
Assignment2-Mlops/
├── .env.example             # Documented environment configuration template
├── .gitignore               # Comprehensive Git exclusions
├── .github/
│   └── workflows/
│       └── ci.yml           # Automated CI testing across Python 3.10-3.13
├── README.md                # Documentation and architecture guide
├── requirements.txt         # Production and development dependencies
├── pyproject.toml           # Project metadata and test configuration
├── agent.py                 # Required CLI entry point
├── tools.py                 # Sandboxed repository inspection tools
├── sample_report.json       # Authentic example agent audit report
├── agent_core/
│   ├── __init__.py          # Package initialization
│   ├── cloner.py            # Temporary workspace isolation and safe cleanup
│   ├── llm_client.py        # Multi-provider client (Groq, Gemini, OpenRouter, Mock)
│   ├── loop.py              # Observe-Reason-Select-Execute-Report agent loop
│   ├── rules.py             # 9-area DevOps heuristic rules catalog
│   └── schemas.py           # Pydantic models, JSON contracts, and secret masking
└── tests/
    ├── __init__.py
    ├── test_agent_loop.py   # Agent reasoning loop tests
    ├── test_cli.py          # End-to-end CLI execution tests
    ├── test_rules.py        # Heuristic and evidence rule tests
    ├── test_schemas.py      # Schema validation and secret redaction tests
    └── test_tools.py        # Sandboxed inspection tools tests
```

---

## 10. License

This project is licensed under the MIT License - see the LICENSE file for details.
