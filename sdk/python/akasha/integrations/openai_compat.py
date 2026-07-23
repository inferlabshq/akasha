"""
Akasha wrapper for OpenAI-compatible APIs.

Covers: OpenAI, Ollama, LM Studio, LiteLLM, and any other provider
that exposes an OpenAI-compatible /v1/chat/completions endpoint.

Usage::

    from akasha.integrations.openai_compat import AkashaOpenAI

    # OpenAI (cloud)
    client = AkashaOpenAI(
        agent_id="my-agent",
        api_key="agt_...",
        llm_api_key="sk-...",
    )

    # Ollama (local — no sensitive data leaves the machine at all)
    client = AkashaOpenAI(
        agent_id="my-agent",
        api_key="agt_...",
        base_url="http://localhost:11434/v1",
        llm_api_key="ollama",
    )

    # LM Studio (local)
    client = AkashaOpenAI(
        agent_id="my-agent",
        api_key="agt_...",
        base_url="http://localhost:1234/v1",
        llm_api_key="lm-studio",
    )

    # LiteLLM proxy (routes to any backend)
    client = AkashaOpenAI(
        agent_id="my-agent",
        api_key="agt_...",
        base_url="http://localhost:8000/v1",
        llm_api_key="litellm",
    )

    # Use exactly like openai.OpenAI():
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "card 4111111111111111"}],
    )
    # → card number vaulted before reaching the model

    # Full tool loop:
    result = client.run(
        model="llama3",
        tools=my_tools,
        tool_executor=execute_fn,
        messages=[...],
        task="Process refund",
    )
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from akasha.client import Akasha
from .base import VaultInterceptor

try:
    import openai as _openai
except ImportError:
    _openai = None

# Known local model base URLs and their display names.
LOCAL_PROVIDERS = {
    "http://localhost:11434": "ollama",
    "http://localhost:11434/v1": "ollama",
    "http://localhost:1234": "lm-studio",
    "http://localhost:1234/v1": "lm-studio",
    "http://localhost:8000": "litellm",
    "http://localhost:8000/v1": "litellm",
}


class AkashaOpenAI:
    """
    Wraps openai.OpenAI (or any compatible client) with vault interception.

    Args:
        agent_id:    Akasha agent identifier.
        api_key:     Akasha agent API key (agt_...).
        llm_api_key: API key for the LLM provider. Use "ollama", "lm-studio",
                     or "litellm" for local providers that don't need real keys.
        base_url:    Override the API base URL. Set this to point at Ollama,
                     LM Studio, LiteLLM, or any OpenAI-compatible endpoint.
        vault_socket:    Path to Akasha daemon socket.
        vault_http_port: Akasha HTTP fallback port.
        run_id:      Optional run ID for correlating audit events.
    """

    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        vault_socket: Optional[str] = None,
        vault_http_port: int = 7743,
        run_id: Optional[str] = None,
        vault_client: Optional[Akasha] = None,
        **openai_kwargs,
    ):
        if _openai is None:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )

        if vault_client is not None:
            self._vault = vault_client
        else:
            vault_kwargs = {"agent_id": agent_id}
            if api_key:
                vault_kwargs["api_key"] = api_key
            if vault_socket:
                vault_kwargs["socket_path"] = vault_socket
            if vault_http_port != 7743:
                vault_kwargs["http_port"] = vault_http_port
            if run_id:
                vault_kwargs["run_id"] = run_id
            self._vault = Akasha(**vault_kwargs)
        self._interceptor = VaultInterceptor(self._vault, run_id=run_id)
        self._run_id = run_id
        self._base_url = base_url
        self._provider = LOCAL_PROVIDERS.get(base_url or "", "openai")

        client_kwargs = {}
        if llm_api_key:
            client_kwargs["api_key"] = llm_api_key
        elif self._provider != "openai":
            client_kwargs["api_key"] = self._provider  # dummy key for local
        if base_url:
            client_kwargs["base_url"] = base_url
        client_kwargs.update(openai_kwargs)

        self._client = _openai.OpenAI(**client_kwargs)
        self.chat = _AkashaChat(self._client, self._interceptor)

    @property
    def is_local(self) -> bool:
        """True if pointing at a local model (Ollama, LM Studio, LiteLLM)."""
        return self._provider != "openai"

    def run(
        self,
        model: str,
        tools: list[dict],
        tool_executor: Callable[[str, Any], Any],
        messages: list[dict],
        *,
        task: str = "",
        reasoning_trace: str = "",
        max_iterations: int = 10,
        **create_kwargs,
    ):
        """
        Run the full tool use loop with vault interception at every step.

        Args:
            model:          Model name (e.g. "gpt-4o", "llama3", "mistral").
            tools:          OpenAI-format tool definitions.
            tool_executor:  fn(name: str, arguments: dict) -> Any
            messages:       Initial message list.
            task:           Task description for audit log.
            reasoning_trace: Agent reasoning for audit log.
            max_iterations: Safety limit on tool rounds.
        """
        msgs = list(messages)

        for _ in range(max_iterations):
            response = self.chat.completions.create(
                model=model,
                tools=tools,
                messages=msgs,
                task=task,
                reasoning_trace=reasoning_trace,
                tool_choice="auto",
                **create_kwargs,
            )

            choice = response.choices[0]
            finish = choice.finish_reason

            if finish != "tool_calls" or not choice.message.tool_calls:
                return response

            tool_calls = choice.message.tool_calls
            msgs.append(choice.message)  # append assistant message

            for tc in tool_calls:
                fn_name = tc.function.name

                # Resolve vault tokens in arguments before execution.
                resolved_args_str = self._interceptor.resolve_json_arguments(
                    tc.function.arguments, fn_name, task=task
                )
                try:
                    resolved_args = json.loads(resolved_args_str)
                except json.JSONDecodeError:
                    resolved_args = resolved_args_str

                # Execute with real values.
                raw_result = tool_executor(fn_name, resolved_args)

                # Vault sensitive content before sending back to model.
                clean_result = self._interceptor.scan_tool_result(
                    raw_result, tool_name=fn_name, task=task
                )
                if not isinstance(clean_result, str):
                    clean_result = json.dumps(clean_result)

                msgs.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": clean_result,
                })

        return response


class _AkashaChat:
    """Proxies openai.chat with vault interception."""

    def __init__(self, client, interceptor: VaultInterceptor):
        self._client = client
        self._interceptor = interceptor
        self.completions = _AkashaCompletions(client, interceptor)


class _AkashaCompletions:
    """Proxies openai.chat.completions with vault interception."""

    def __init__(self, client, interceptor: VaultInterceptor):
        self._client = client
        self._interceptor = interceptor

    def create(
        self,
        *,
        messages: list[dict],
        task: str = "",
        reasoning_trace: str = "",
        **kwargs,
    ):
        """
        Drop-in for openai.chat.completions.create().

        Scans all message content before sending to the model.
        """
        clean_messages = self._interceptor.scan_messages(messages, task=task)
        return self._client.chat.completions.create(
            messages=clean_messages, **kwargs
        )
