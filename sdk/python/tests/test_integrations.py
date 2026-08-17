"""
Tests for Akasha LLM integrations.

Uses unittest.mock to stub out the Anthropic and OpenAI clients,
and respx to mock the Akasha daemon HTTP calls.
No real LLM API keys or running daemon required.
"""

import json
from unittest.mock import MagicMock, patch
import pytest
import httpx
import respx

from akasha.integrations.base import VaultInterceptor
from akasha.client import Akasha


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_vault(base_url="http://localhost:7743") -> Akasha:
    vault = Akasha.__new__(Akasha)
    vault.agent_id = "test-agent"
    vault.api_key = None
    vault.run_id = None
    vault._socket_path = "/nonexistent.sock"
    vault._http_port = 7743
    vault._timeout = 5.0
    vault._client = httpx.Client(base_url=base_url, timeout=5.0)
    return vault


def make_interceptor() -> VaultInterceptor:
    return VaultInterceptor(make_vault())


# ---------------------------------------------------------------------------
# VaultInterceptor — base logic
# ---------------------------------------------------------------------------

@respx.mock
def test_scan_text_sensitive():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={
            "clean_content": "SSN is vault://abc123",
            "vaulted": True,
            "token": "vault://abc123",
            "category": "SSN",
            "risk": "critical",
        }
    ))
    ic = make_interceptor()
    result = ic.scan_text("SSN is 429-21-0001", tool_name="lookup")
    assert result == "SSN is vault://abc123"


@respx.mock
def test_scan_text_clean():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "hello world", "vaulted": False}
    ))
    ic = make_interceptor()
    result = ic.scan_text("hello world")
    assert result == "hello world"


@respx.mock
def test_scan_messages_string_content():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "card vault://tok1", "vaulted": True}
    ))
    ic = make_interceptor()
    msgs = [{"role": "user", "content": "card 4111111111111111"}]
    clean = ic.scan_messages(msgs)
    assert clean[0]["content"] == "card vault://tok1"


@respx.mock
def test_scan_messages_structured_content():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "vault://tok1", "vaulted": True}
    ))
    ic = make_interceptor()
    msgs = [{
        "role": "user",
        "content": [{"type": "text", "text": "429-21-0001"}]
    }]
    clean = ic.scan_messages(msgs)
    assert clean[0]["content"][0]["text"] == "vault://tok1"


@respx.mock
def test_resolve_text_replaces_tokens():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "429-21-0001"}
    ))
    ic = make_interceptor()
    result = ic.resolve_text("SSN is vault://abc123", tool_name="lookup")
    assert result == "SSN is 429-21-0001"


@respx.mock
def test_resolve_tool_input_dict():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "real-secret"}
    ))
    ic = make_interceptor()
    resolved = ic.resolve_tool_input("my_tool", {"key": "vault://abc123"})
    assert resolved == {"key": "real-secret"}


@respx.mock
def test_resolve_json_arguments():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "4111111111111111"}
    ))
    ic = make_interceptor()
    args = json.dumps({"card": "vault://tok1", "amount": 100})
    resolved = ic.resolve_json_arguments(args, "charge_card")
    parsed = json.loads(resolved)
    assert parsed["card"] == "4111111111111111"
    assert parsed["amount"] == 100  # non-token values unchanged


@respx.mock
def test_scan_tool_result():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "balance: vault://tok1", "vaulted": True}
    ))
    ic = make_interceptor()
    result = ic.scan_tool_result("balance: $50,000", tool_name="get_balance")
    assert "vault://" in result


def test_resolve_text_no_tokens():
    ic = make_interceptor()
    result = ic.resolve_text("no tokens here")
    assert result == "no tokens here"


def test_resolve_text_unknown_token_left_intact():
    """Unknown tokens should be left as-is, not crash."""
    with respx.mock:
        respx.post("http://localhost:7743/retrieve").mock(
            return_value=httpx.Response(404, text="token not found")
        )
        ic = make_interceptor()
        result = ic.resolve_text("vault://doesnotexist")
        # Token left in place — tool call still goes through
        assert "vault://doesnotexist" in result


# ---------------------------------------------------------------------------
# AkashaAnthropic — mocked Anthropic client
# ---------------------------------------------------------------------------

@respx.mock
def test_anthropic_messages_create_scans_content():
    """messages.create() should scan outbound content before sending to Claude."""
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={
            "clean_content": "SSN is vault://abc123",
            "vaulted": True,
            "token": "vault://abc123",
        }
    ))

    with patch("akasha.integrations.anthropic._anthropic") as mock_ant:
        mock_client = MagicMock()
        mock_ant.Anthropic.return_value = mock_client
        mock_client.messages.create.return_value = MagicMock(stop_reason="end_turn")

        from akasha.integrations.anthropic import AkashaAnthropic
        client = AkashaAnthropic(
            agent_id="test",
            anthropic_api_key="sk-test",
            vault_client=make_vault(),
        )

        client.messages.create(
            model="claude-opus-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "SSN is 429-21-0001"}],
        )

        call_kwargs = mock_client.messages.create.call_args[1]
        sent_messages = call_kwargs["messages"]
        assert sent_messages[0]["content"] == "SSN is vault://abc123"


@respx.mock
def test_anthropic_run_tool_loop():
    """run() should intercept tool calls, resolve tokens, and vault results."""

    # Wrap call for outbound message scan.
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "user message", "vaulted": False}
    ))
    # Retrieve call for resolving vault token in tool input.
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "429-21-0001"}
    ))

    with patch("akasha.integrations.anthropic._anthropic") as mock_ant:
        # First response: tool call with vault token in input
        tool_use_block = MagicMock()
        tool_use_block.type = "tool_use"
        tool_use_block.id = "toolu_123"
        tool_use_block.name = "lookup_account"
        tool_use_block.input = {"ssn": "vault://abc123"}

        first_response = MagicMock()
        first_response.stop_reason = "tool_use"
        first_response.content = [tool_use_block]

        # Second response: done
        second_response = MagicMock()
        second_response.stop_reason = "end_turn"
        second_response.content = []

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = [first_response, second_response]
        mock_ant.Anthropic.return_value = mock_client

        tool_calls = []
        def executor(name, input_data):
            tool_calls.append((name, input_data))
            return "Account found"

        from akasha.integrations.anthropic import AkashaAnthropic
        client = AkashaAnthropic(
            agent_id="test",
            anthropic_api_key="sk-test",
            vault_client=make_vault(),
        )
        client.run(
            model="claude-opus-4-5",
            tools=[],
            tool_executor=executor,
            messages=[{"role": "user", "content": "user message"}],
            task="Test task",
            max_tokens=100,
        )

        # Tool was called with resolved value, not vault token
        assert len(tool_calls) == 1
        assert tool_calls[0] == ("lookup_account", {"ssn": "429-21-0001"})


# ---------------------------------------------------------------------------
# AkashaOpenAI — mocked OpenAI client
# ---------------------------------------------------------------------------

@respx.mock
def test_openai_completions_create_scans_content():
    """chat.completions.create() should scan outbound content."""
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "card vault://tok1", "vaulted": True}
    ))

    with patch("akasha.integrations.openai_compat._openai") as mock_oai:
        mock_client = MagicMock()
        mock_oai.OpenAI.return_value = mock_client
        mock_client.chat.completions.create.return_value = MagicMock()

        from akasha.integrations.openai_compat import AkashaOpenAI
        client = AkashaOpenAI(
            agent_id="test",
            llm_api_key="sk-test",
            vault_client=make_vault(),
        )
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "card 4111111111111111"}],
        )

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        sent = call_kwargs["messages"]
        assert sent[0]["content"] == "card vault://tok1"


@respx.mock
def test_openai_run_tool_loop():
    """run() resolves vault tokens before tool execution."""
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "msg", "vaulted": False}
    ))
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "real-api-key"}
    ))

    with patch("akasha.integrations.openai_compat._openai") as mock_oai:
        # First: tool call with vault token
        tc = MagicMock()
        tc.id = "call_123"
        tc.function.name = "call_api"
        tc.function.arguments = json.dumps({"api_key": "vault://tok1"})

        first_choice = MagicMock()
        first_choice.finish_reason = "tool_calls"
        first_choice.message.tool_calls = [tc]

        second_choice = MagicMock()
        second_choice.finish_reason = "stop"
        second_choice.message.tool_calls = None

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[first_choice]),
            MagicMock(choices=[second_choice]),
        ]
        mock_oai.OpenAI.return_value = mock_client

        tool_calls = []
        def executor(name, args):
            tool_calls.append((name, args))
            return "ok"

        from akasha.integrations.openai_compat import AkashaOpenAI
        client = AkashaOpenAI(
            agent_id="test",
            llm_api_key="sk-test",
            vault_client=make_vault(),
        )
        client.run(
            model="gpt-4o",
            tools=[],
            tool_executor=executor,
            messages=[{"role": "user", "content": "msg"}],
        )

        assert tool_calls[0] == ("call_api", {"api_key": "real-api-key"})


def test_openai_is_local_for_ollama():
    with patch("akasha.integrations.openai_compat._openai") as mock_oai:
        mock_oai.OpenAI.return_value = MagicMock()
        from akasha.integrations.openai_compat import AkashaOpenAI
        client = AkashaOpenAI(
            agent_id="test",
            api_key="agt_test_key",
            base_url="http://localhost:11434/v1",
            llm_api_key="ollama",
        )
        assert client.is_local is True


def test_openai_is_not_local_for_openai():
    with patch("akasha.integrations.openai_compat._openai") as mock_oai:
        mock_oai.OpenAI.return_value = MagicMock()
        from akasha.integrations.openai_compat import AkashaOpenAI
        client = AkashaOpenAI(agent_id="test", api_key="agt_test_key", llm_api_key="sk-test")
        assert client.is_local is False
