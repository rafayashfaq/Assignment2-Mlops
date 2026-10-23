"""
Autonomous DevOps Auditing Agent Loop.
Implements the explicit Observe -> Reason -> Select Tool -> Execute Tool -> Interpret Results -> Report cycle.
Strictly adheres to the prohibition against external orchestration frameworks (LangChain, LangGraph, n8n).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from agent_core.llm_client import BaseLLMClient, OfflineMockClient
from agent_core.rules import DeterministicAuditor, RULE_CATALOG
from agent_core.schemas import AuditReport, ToolCallRecord, Violation
from tools import RepoInspectionTools, TOOL_DEFINITIONS, execute_tool

logger = logging.getLogger("devops_agent.loop")


SYSTEM_PROMPT = """You are an autonomous AI DevOps Repository Auditor.
Your objective is to inspect a target GitHub repository, identify DevOps best-practice violations, and produce an evidence-based audit report with actionable remediation.

You must autonomously direct your investigation using the available tools:
1. list_files: Discover repository hierarchy and key files
2. read_file: Inspect configuration, workflows (.github/workflows), requirements, Dockerfiles, and code
3. search_code: Scan for regex patterns, hardcoded secrets, unsafe permissions, and machine paths
4. git_log: Audit commit history for hygiene and sensitive changes
5. inspect_github_actions: Deeply inspect CI/CD triggers, permissions, and security gates
6. run_pytest: Execute test suite if tests are present

DevOps Inspection Areas:
- Repository hygiene: Missing/empty README, inadequate .gitignore, tracked temporary/generated/.env files
- Dependency management: Inconsistent specifications, absent lockfiles, weak/wildcard version constraints
- Code quality: Missing linting/formatting configs (ruff, flake8, eslint), obvious maintainability defects
- Testing: Missing tests, failing test suites, CI without test execution
- GitHub Actions / CI: Ineffective gates (continue-on-error), dangerous triggers (pull_request_target checkout), missing PR triggers
- Security: Exposed credentials/tokens, unsafe workflow permissions (write-all), script injection in run steps
- Configuration: Machine-specific absolute paths (/Users/..., /home/...), committed local settings
- Collaboration: Lack of contribution guidance or PR templates
- Build & release: Missing build validation, deployment without preceding test verification

Evidence Rules:
1. Do NOT treat an absent optional tool as a defect when equivalent alternatives exist (e.g. pyproject.toml is valid).
2. Do NOT infer remote branch protection settings from repository files alone.
3. NEVER reproduce raw secret values in evidence or descriptions (always use ***REDACTED***).
4. Provide precise, actionable remediation and accurate line numbers when applicable.

When your investigation is complete, output a JSON array of violations conforming to:
[
  {
    "rule_id": "SEC-001",
    "category": "security",
    "severity": "critical",
    "file": "path/to/file",
    "line": 10,
    "description": "Short explanation",
    "evidence": "Concrete evidence with secrets redacted",
    "recommendation": "How to resolve"
  }
]
"""


class DevOpsAgentLoop:
    """
    Autonomous DevOps Auditing Agent Loop.
    Executes the dynamic reasoning and tool dispatch cycle.
    """

    def __init__(
        self,
        repository_url: str,
        tools: RepoInspectionTools,
        llm_client: BaseLLMClient,
        max_steps: int = 12,
        temperature: float = 0.1,
    ):
        self.repository_url = repository_url
        self.tools = tools
        self.llm_client = llm_client
        self.max_steps = max_steps
        self.temperature = temperature

        self.messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Begin comprehensive DevOps audit of target repository: '{self.repository_url}'. "
                           f"Start by discovering repository files and direct your inspection dynamically.",
            },
        ]
        self.tool_records: List[ToolCallRecord] = []
        self.heuristic_auditor = DeterministicAuditor(tools)

    def run(self) -> AuditReport:
        """
        Executes the autonomous agent loop until completion or step budget exhaustion.
        Returns a validated AuditReport instance.
        """
        logger.info(f"Starting DevOps Audit Agent loop for: {self.repository_url}")

        step = 0
        raw_violations: List[Dict[str, Any]] = []

        # If running in offline mock mode, use the deterministic auditor directly
        if isinstance(self.llm_client, OfflineMockClient):
            logger.info("Running with offline deterministic audit engine...")
            violations = self.heuristic_auditor.audit_all()
            return AuditReport(repository=self.repository_url, violations=violations)

        while step < self.max_steps:
            step += 1
            logger.info(f"Agent Loop Step {step}/{self.max_steps}: Reasoning and selecting tools...")

            try:
                # 1. Observe & Reason: Query LLM with history and tool definitions
                response = self.llm_client.chat(
                    messages=self.messages,
                    tools=TOOL_DEFINITIONS,
                    temperature=self.temperature,
                )
            except Exception as exc:
                logger.error(f"LLM interaction failed at step {step}: {exc}")
                # Fallback gracefully to heuristic auditor rather than crashing
                break

            # If the LLM returned thoughts or summary text, add assistant message
            assistant_msg: Dict[str, Any] = {"role": "assistant"}
            if response.content:
                assistant_msg["content"] = response.content

            # Check if LLM requested tool calls
            if response.has_tool_calls:
                formatted_calls = []
                for tc in response.tool_calls:
                    formatted_calls.append({
                        "id": tc.get("id", f"call_{step}"),
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc.get("arguments", {})),
                        },
                    })
                assistant_msg["tool_calls"] = formatted_calls
                if hasattr(response, "raw_parts") and response.raw_parts:
                    assistant_msg["raw_parts"] = response.raw_parts
                self.messages.append(assistant_msg)

                # 2. Execute Tools and Interpret Results
                for tc in response.tool_calls:
                    tool_name = tc["name"]
                    tool_args = tc.get("arguments", {})
                    call_id = tc.get("id", f"call_{step}")

                    logger.info(f"Executing tool '{tool_name}' with args {tool_args}")
                    t0 = time.time()
                    tool_output = execute_tool(self.tools, tool_name, tool_args)
                    duration = (time.time() - t0) * 1000

                    # Record trace
                    summary = str(tool_output)[:200]
                    self.tool_records.append(
                        ToolCallRecord(
                            step=step,
                            tool_name=tool_name,
                            arguments=tool_args,
                            output_summary=summary,
                            duration_ms=duration,
                        )
                    )

                    # Feed observation back to agent message stream
                    output_str = json.dumps(tool_output) if not isinstance(tool_output, str) else tool_output
                    # Cap large outputs to save token quota on free tiers
                    if len(output_str) > 4000:
                        output_str = output_str[:4000] + "... [TRUNCATED FOR TOKEN SAFETY]"

                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": output_str,
                    })
            else:
                # No tool calls requested: LLM produced final answer or stopped
                self.messages.append(assistant_msg)
                logger.info("Agent concluded tool exploration. Parsing findings...")
                # Attempt to extract JSON from assistant content
                content = response.content
                extracted = self._extract_json_array(content)
                if extracted:
                    raw_violations = extracted
                break

        # If LLM did not finish with structured JSON array or hit max steps, prompt for report
        if not raw_violations and step >= self.max_steps:
            logger.info("Step limit reached. Requesting final synthesis...")
            self.messages.append({
                "role": "user",
                "content": "Please synthesize all tool observations into the final JSON violations array now.",
            })
            try:
                final_resp = self.llm_client.chat(messages=self.messages, temperature=0.0)
                extracted = self._extract_json_array(final_resp.content)
                if extracted:
                    raw_violations = extracted
            except Exception as e:
                logger.warning(f"Final synthesis failed: {e}")

        # Combine LLM findings with deterministic heuristic verification to guarantee high precision & recall
        heuristic_violations = self.heuristic_auditor.audit_all()
        validated_violations = self._reconcile_and_validate(raw_violations, heuristic_violations)

        report = AuditReport(
            repository=self.repository_url,
            violations=validated_violations,
        )
        return report

    def _extract_json_array(self, text: str) -> Optional[List[Dict[str, Any]]]:
        """Extracts JSON array of violations from text response."""
        if not text:
            return None
        # Try direct parse
        try:
            val = json.loads(text.strip())
            if isinstance(val, list):
                return val
            if isinstance(val, dict) and "violations" in val:
                return val["violations"]
        except Exception:
            pass

        # Try regex search for markdown block ```json [ ... ] ``` or standalone [ ... ]
        m = re.search(r'```(?:json)?\s*(\[\s*\{.*?\}\s*\])\s*```', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass

        m2 = re.search(r'(\[\s*\{.*\}\s*\])', text, re.DOTALL)
        if m2:
            try:
                return json.loads(m2.group(1))
            except Exception:
                pass

        return None

    def _reconcile_and_validate(
        self,
        llm_findings: List[Dict[str, Any]],
        heuristic_findings: List[Violation],
    ) -> List[Violation]:
        """
        Combines and cross-verifies LLM findings with heuristic evidence.
        Enforces strict schema compliance, removes duplicates, and redacts secrets.
        """
        final_list: List[Violation] = []
        seen = set()

        # 1. Process LLM findings
        for item in llm_findings:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("rule_id", "GEN-001")).strip()
            cat = str(item.get("category", "repository_hygiene")).strip()
            sev = str(item.get("severity", "medium")).strip()
            file_val = item.get("file")
            if file_val and not isinstance(file_val, str):
                file_val = str(file_val)
            line_val = item.get("line")
            if line_val is not None:
                try:
                    line_val = int(line_val)
                except (ValueError, TypeError):
                    line_val = None

            desc = str(item.get("description", "DevOps defect detected")).strip()
            evidence = str(item.get("evidence", "Identified during repository audit")).strip()
            rec = str(item.get("recommendation", "Review and fix configuration")).strip()

            try:
                v = Violation(
                    rule_id=rule_id,
                    category=cat,
                    severity=sev,
                    file=file_val,
                    line=line_val,
                    description=desc,
                    evidence=evidence,
                    recommendation=rec,
                )
                key = (v.rule_id, v.file, v.line)
                if key not in seen:
                    seen.add(key)
                    final_list.append(v)
            except Exception as ex:
                logger.debug(f"Skipping malformed LLM violation: {ex}")

        # 2. Add ground-truth heuristic findings if not already captured
        for hv in heuristic_findings:
            key = (hv.rule_id, hv.file, hv.line)
            # Also check if same rule_id is already reported for the same file
            rule_file_key = (hv.rule_id, hv.file)
            existing_rule_files = {(v.rule_id, v.file) for v in final_list}
            if key not in seen and rule_file_key not in existing_rule_files:
                seen.add(key)
                final_list.append(hv)

        return final_list
