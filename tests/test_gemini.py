import os
import unittest.mock as mock
import pytest

from agent_core.llm_client import GeminiFreeClient, _convert_schema_to_gemini, create_llm_client


def test_convert_schema_to_gemini():
    schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "file path"},
            "lines": {"type": "integer"},
            "flags": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": ["path"],
    }
    converted = _convert_schema_to_gemini(schema)
    assert converted["type"] == "OBJECT"
    assert converted["properties"]["path"]["type"] == "STRING"
    assert converted["properties"]["lines"]["type"] == "INTEGER"
    assert converted["properties"]["flags"]["type"] == "ARRAY"
    assert converted["properties"]["flags"]["items"]["type"] == "STRING"


def test_create_llm_client_prioritizes_gemini(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyFakeKey123")
    monkeypatch.delenv("DEFAULT_LLM_PROVIDER", raising=False)
    client = create_llm_client()
    assert isinstance(client, GeminiFreeClient)
    assert client.api_key == "AIzaSyFakeKey123"
    assert client.model == "gemini-3.5-flash-lite"


def test_gemini_client_parses_function_call(monkeypatch):
    client = GeminiFreeClient(api_key="AIzaSyFakeKey123")

    fake_response = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "functionCall": {
                                "name": "list_files",
                                "args": {"directory": "src", "max_depth": 2},
                            }
                        }
                    ],
                }
            }
        ]
    }

    with mock.patch("requests.post") as mock_post:
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = fake_response
        mock_post.return_value = mock_resp

        messages = [{"role": "user", "content": "List files in src"}]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "list_files",
                    "description": "List files",
                    "parameters": {"type": "object", "properties": {"directory": {"type": "string"}}},
                },
            }
        ]

        resp = client.chat(messages=messages, tools=tools)
        assert resp.has_tool_calls is True
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0]["name"] == "list_files"
        assert resp.tool_calls[0]["arguments"] == {"directory": "src", "max_depth": 2}
