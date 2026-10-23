"""
Multi-provider LLM Client module.
Specialized for 100% Free APIs (0 fee, maximum daily prompts):
1. Groq Cloud (Default): Up to 14,400 free requests/day with Llama 3.3 70B & 3.1 8B.
2. Google Gemini Free Tier: Up to 1,500 free requests/day.
3. OpenRouter Free Models: Community free models with zero fee.
4. Offline Rule Engine / Mock: 0 fee, zero network, unlimited local prompts.

Framework Restriction Compliance:
Implements custom agent reasoning, tool dispatching, and control flow in pure Python.
No LangChain, No LangGraph, No CrewAI, No prebuilt agent platforms.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import requests

logger = logging.getLogger("devops_agent.llm")


class LLMResponse:
    """Standardized LLM response object."""
    def __init__(
        self,
        content: Optional[str] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        raw_response: Any = None,
        raw_parts: Optional[List[Dict[str, Any]]] = None,
    ):
        self.content = content or ""
        self.tool_calls = tool_calls or []
        self.raw_response = raw_response
        self.raw_parts = raw_parts or []

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class BaseLLMClient:
    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.1,
    ) -> LLMResponse:
        raise NotImplementedError


class GroqClient(BaseLLMClient):
    """
    Client for Groq Cloud API.
    Provider: Groq (https://console.groq.com)
    Pricing: 100% Free ($0.00 / month, No Credit Card Required)
    Free Limits: 14,400 requests/day, 30 requests/minute
    Default Model: llama-3.3-70b-versatile or llama-3.1-8b-instant
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.model = model or os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
        if not self.api_key:
            raise ValueError(
                "GROQ_API_KEY is not set. Get a 100% free API key with 14,400 requests/day "
                "at https://console.groq.com/keys and set GROQ_API_KEY in your .env or environment."
            )
        try:
            from groq import Groq
            self.client = Groq(api_key=self.api_key)
        except ImportError:
            self.client = None

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.1,
    ) -> LLMResponse:
        # If groq package is present, use it; otherwise fallback to OpenAI-compatible endpoint
        max_retries = 3
        backoff = 2.0

        for attempt in range(max_retries):
            try:
                if self.client:
                    kwargs: Dict[str, Any] = {
                        "model": self.model,
                        "messages": messages,
                        "temperature": temperature,
                    }
                    if tools:
                        kwargs["tools"] = tools
                        kwargs["tool_choice"] = "auto"

                    response = self.client.chat.completions.create(**kwargs)
                    choice = response.choices[0]
                    message = choice.message

                    tool_calls = []
                    if message.tool_calls:
                        for tc in message.tool_calls:
                            try:
                                args = json.loads(tc.function.arguments) if isinstance(tc.function.arguments, str) else tc.function.arguments
                            except Exception:
                                args = {}
                            tool_calls.append({
                                "id": tc.id,
                                "name": tc.function.name,
                                "arguments": args,
                            })

                    return LLMResponse(
                        content=message.content or "",
                        tool_calls=tool_calls,
                        raw_response=response,
                    )
                else:
                    # Direct HTTP to Groq OpenAI-compatible endpoint
                    headers = {
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    }
                    payload: Dict[str, Any] = {
                        "model": self.model,
                        "messages": messages,
                        "temperature": temperature,
                    }
                    if tools:
                        payload["tools"] = tools

                    resp = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=45,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    choice = data["choices"][0]
                    msg = choice.get("message", {})

                    tool_calls = []
                    for tc in msg.get("tool_calls", []):
                        fn = tc.get("function", {})
                        raw_args = fn.get("arguments", "{}")
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                        tool_calls.append({
                            "id": tc.get("id", "call_1"),
                            "name": fn.get("name"),
                            "arguments": args,
                        })

                    return LLMResponse(
                        content=msg.get("content", ""),
                        tool_calls=tool_calls,
                        raw_response=data,
                    )
            except Exception as exc:
                is_rate_limit = "429" in str(exc) or "rate" in str(exc).lower()
                if is_rate_limit and attempt < max_retries - 1:
                    logger.warning(f"Groq rate limit reached, waiting {backoff}s before retry...")
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                logger.error(f"Groq API error on attempt {attempt + 1}: {exc}")
                if attempt == max_retries - 1:
                    raise exc


def _convert_schema_to_gemini(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively converts standard JSON Schema to Gemini FunctionDeclaration format."""
    if not isinstance(schema, dict):
        return schema
    converted: Dict[str, Any] = {}
    for k, v in schema.items():
        if k == "type" and isinstance(v, str):
            converted[k] = v.upper()
        elif k == "properties" and isinstance(v, dict):
            converted[k] = {pk: _convert_schema_to_gemini(pv) for pk, pv in v.items()}
        elif k == "items" and isinstance(v, dict):
            converted[k] = _convert_schema_to_gemini(v)
        else:
            converted[k] = v
    return converted


class GeminiFreeClient(BaseLLMClient):
    """
    Client for Google Gemini Free Tier via Google AI Studio.
    Provider: Google AI Studio (https://aistudio.google.com/)
    Pricing: 100% Free ($0.00 / month, No Credit Card Required)
    Free Limits: 1,500 requests/day, 15 requests/minute, 1,000,000 tokens/minute
    Default Model: gemini-1.5-flash or gemini-2.0-flash
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")
        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY is not set. Get your 100% free Gemini API key at "
                "https://aistudio.google.com/ and set GEMINI_API_KEY in your .env file."
            )
        # List of candidate models to fall back through if a specific model is unreachable or deprecated
        models_order = [self.model, "gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-2.5-flash-lite", "gemini-1.5-flash"]
        self.candidate_models: List[str] = []
        for m in models_order:
            if m not in self.candidate_models:
                self.candidate_models.append(m)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.1,
    ) -> LLMResponse:
        contents = []
        system_instruction = None

        for msg in messages:
            role = msg.get("role")
            if role == "system":
                system_instruction = {"parts": [{"text": msg.get("content", "")}]}
            elif role == "user":
                contents.append({"role": "user", "parts": [{"text": msg.get("content", "")}]})
            elif role == "assistant":
                if msg.get("raw_parts"):
                    contents.append({"role": "model", "parts": msg["raw_parts"]})
                else:
                    parts: List[Dict[str, Any]] = []
                    if msg.get("content"):
                        parts.append({"text": msg.get("content")})
                    for tc in msg.get("tool_calls", []):
                        fn = tc.get("function", {})
                        raw_args = fn.get("arguments", "{}")
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                        parts.append({"functionCall": {"name": fn.get("name"), "args": args}})
                    if parts:
                        contents.append({"role": "model", "parts": parts})
            elif role == "tool":
                fn_name = msg.get("name", "tool")
                raw_content = msg.get("content", "")
                try:
                    content_obj = json.loads(raw_content) if isinstance(raw_content, str) else raw_content
                except Exception:
                    content_obj = {"output": raw_content}
                contents.append({
                    "role": "user",
                    "parts": [{
                        "functionResponse": {
                            "name": fn_name,
                            "response": {"result": content_obj}
                        }
                    }]
                })

        body: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if system_instruction:
            body["systemInstruction"] = system_instruction

        # Convert tool definitions to Gemini function_declarations format
        if tools:
            function_declarations = []
            for t in tools:
                fn = t.get("function", {})
                params = fn.get("parameters", {})
                converted_params = _convert_schema_to_gemini(params)
                function_declarations.append({
                    "name": fn.get("name"),
                    "description": fn.get("description", ""),
                    "parameters": converted_params,
                })
            body["tools"] = [{"function_declarations": function_declarations}]

        # Try models in candidate order if 404/unreachable occurs
        last_error = None
        for candidate_model in self.candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate_model}:generateContent?key={self.api_key}"
            max_retries = 2
            backoff = 2.0

            for attempt in range(max_retries):
                try:
                    resp = requests.post(url, json=body, timeout=25)
                    if resp.status_code == 429:
                        if attempt < max_retries - 1:
                            logger.warning(f"Gemini rate limit (429) on {candidate_model}, retrying...")
                            time.sleep(backoff)
                            backoff *= 2
                            continue
                    if resp.status_code == 404:
                        # Model unavailable, try next candidate model
                        logger.warning(f"Gemini model {candidate_model} returned 404, trying next available model...")
                        break

                    resp.raise_for_status()
                    data = resp.json()

                    candidates = data.get("candidates", [])
                    if not candidates:
                        return LLMResponse(content="")

                    first = candidates[0]
                    content_obj = first.get("content", {})
                    parts = content_obj.get("parts", [])

                    tool_calls: List[Dict[str, Any]] = []
                    text_parts: List[str] = []

                    for idx, p in enumerate(parts):
                        if "functionCall" in p:
                            fc = p["functionCall"]
                            tool_calls.append({
                                "id": f"gemini_call_{idx + 1}",
                                "name": fc.get("name"),
                                "arguments": fc.get("args", {}),
                            })
                        elif "text" in p:
                            text_parts.append(p["text"])

                    # Successfully received response
                    self.model = candidate_model
                    return LLMResponse(
                        content="\n".join(text_parts),
                        tool_calls=tool_calls,
                        raw_response=data,
                        raw_parts=parts,
                    )
                except Exception as exc:
                    last_error = exc
                    if "404" in str(exc):
                        break
                    if attempt < max_retries - 1 and ("429" in str(exc) or "503" in str(exc)):
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                    logger.debug(f"Gemini attempt failed on {candidate_model}: {exc}")

        if last_error:
            raise last_error
        return LLMResponse(content="")


class OpenAIClient(BaseLLMClient):
    """Client for OpenAI or any OpenAI-compatible API endpoint."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL", None)
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        from openai import OpenAI
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.1,
    ) -> LLMResponse:
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        message = choice.message

        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if isinstance(tc.function.arguments, str) else tc.function.arguments
                except Exception:
                    args = {}
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args,
                })

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            raw_response=response,
        )


class OfflineMockClient(BaseLLMClient):
    """
    Offline/deterministic mock client.
    Allows 100% test coverage and offline verification with zero API fees and zero network calls.
    Simulates intelligent tool selection steps followed by synthesis.
    """

    def __init__(self, step_budget: int = 5):
        self.step_budget = step_budget
        self.step_count = 0

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        self.step_count += 1

        # Check if list_files has been called yet
        tool_messages = [m for m in messages if m.get("role") == "tool"]
        called_tools = [m.get("name") for m in tool_messages]

        if "list_files" not in called_tools and self.step_count == 1:
            return LLMResponse(
                content="I will begin by inspecting the directory structure of the repository to discover key files.",
                tool_calls=[{"id": "call_1", "name": "list_files", "arguments": {"directory": "", "max_depth": 3}}],
            )
        elif "inspect_github_actions" not in called_tools and self.step_count == 2:
            return LLMResponse(
                content="Next, I will inspect GitHub Actions workflows to identify CI/CD triggers and security gates.",
                tool_calls=[{"id": "call_2", "name": "inspect_github_actions", "arguments": {}}],
            )
        elif "git_log" not in called_tools and self.step_count == 3:
            return LLMResponse(
                content="Now I will inspect recent git commits to evaluate commit hygiene.",
                tool_calls=[{"id": "call_3", "name": "git_log", "arguments": {"max_count": 10}}],
            )
        elif "search_code" not in called_tools and self.step_count == 4:
            return LLMResponse(
                content="I will search for potential hardcoded credentials or API tokens in the code.",
                tool_calls=[{"id": "call_4", "name": "search_code", "arguments": {"pattern": "(?i)api[_-]?key"}}],
            )
        else:
            return LLMResponse(
                content="Inspection complete. Synthesizing evidence-based DevOps audit report.",
                tool_calls=[],
            )


def create_llm_client(
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> BaseLLMClient:
    """
    Factory function to initialize the preferred free LLM provider.
    Priority order:
    1. Explicit provider passed as argument
    2. DEFAULT_LLM_PROVIDER in environment (defaults to 'gemini')
    3. Auto-detection based on configured API keys: GEMINI_API_KEY > GROQ_API_KEY > OPENROUTER_API_KEY > OPENAI_API_KEY
    4. Offline mock client if no keys are found
    """
    chosen_provider = (provider or os.environ.get("DEFAULT_LLM_PROVIDER", "")).strip().lower()

    if not chosen_provider:
        if os.environ.get("GEMINI_API_KEY"):
            chosen_provider = "gemini"
        elif os.environ.get("GROQ_API_KEY"):
            chosen_provider = "groq"
        elif os.environ.get("OPENROUTER_API_KEY"):
            chosen_provider = "openrouter"
        elif os.environ.get("OPENAI_API_KEY"):
            chosen_provider = "openai"
        else:
            chosen_provider = "offline"

    if chosen_provider == "gemini":
        return GeminiFreeClient(api_key=api_key, model=model)
    elif chosen_provider == "groq":
        return GroqClient(api_key=api_key, model=model)
    elif chosen_provider in ["openrouter", "openai"]:
        if chosen_provider == "openrouter":
            base_url = "https://openrouter.ai/api/v1"
            key = api_key or os.environ.get("OPENROUTER_API_KEY")
            mdl = model or os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
            return OpenAIClient(api_key=key, model=mdl, base_url=base_url)
        return OpenAIClient(api_key=api_key, model=model)
    elif chosen_provider in ["offline", "mock"]:
        return OfflineMockClient()
    else:
        raise ValueError(f"Unknown LLM provider: '{chosen_provider}'. Supported: gemini, groq, openrouter, openai, offline")
