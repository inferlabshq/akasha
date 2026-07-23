"""
Akasha wrapper for the Anthropic Python SDK.

Drop-in replacement for anthropic.Anthropic() that intercepts all
tool calls and vaults sensitive content automatically.

Usage::

    from akasha.integrations.anthropic import AkashaAnthropic

    client = AkashaAnthropic(
        agent_id="support-bot-v2",
        api_key="agt_support-bot-v2_...",   # Akasha agent key
        anthropic_api_key="sk-ant-...",      # your Anthropic key
    )

    # Identical to anthropic.Anthropic().messages.create(...)
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        tools=[...],
        messages=[{"role": "user", "content": "Look up account for SSN 429-21-0001"}]
    )
    # → SSN is vaulted before reaching Claude, Claude sees vault://... token

    # Full tool loop with automatic interception:
    result = client.run(
        model="claude-opus-4-5",
        tools=my_tools,           # list of tool dicts
        tool_executor=execute_fn, # fn(name, input) -> result
        messages=[...],
        task="Process refund for order #8821",
    )
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from akasha.client import Akasha
from .base import VaultInterceptor

try:
    import anthropic as _anthropic
except ImportError:
    _anthropic = None


class AkashaAnthropic:
    """
    Wraps anthropic.Anthropic with vault interception.

    Args:
        agent_id:        Akasha agent identifier.
        api_key:         Akasha agent API key (agt_...). Optional but recommended —
                         enables server-side identity verification.
        anthropic_api_key: Your Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
        vault_socket:    Path to Akasha daemon socket. Defaults to ~/.akasha/akasha.sock.
        vault_http_port: Akasha HTTP fallback port. Defaults to 7743.
        run_id:          Optional run ID for correlating audit events.
    """

    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        vault_socket: Optional[str] = None,
        vault_http_port: int = 7743,
        run_id: Optional[str] = None,
        vault_client: Optional[Akasha] = None,
        **anthropic_kwargs,
    ):
        if _anthropic is None:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
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

        client_kwargs = {}
        if anthropic_api_key:
            client_kwargs["api_key"] = anthropic_api_key
        client_kwargs.update(anthropic_kwargs)
        self._client = _anthropic.Anthropic(**client_kwargs)

        # Expose messages namespace directly.
        self.messages = _AkashaMessages(self._client, self._interceptor)

    def run(
        self,
        model: str,
        tools: list[dict],
        tool_executor: Callable[[str, dict], Any],
        messages: list[dict],
        *,
        task: str = "",
        reasoning_trace: str = "",
        max_iterations: int = 10,
        **create_kwargs,
    ) -> _anthropic.types.Message if _anthropic else Any:
        """
        Run the full tool use loop with vault interception at every step.

        Akasha automatically:
          - Vaults sensitive content in outbound messages
          - Resolves vault tokens in Claude's tool call arguments before execution
          - Vaults sensitive content in tool results before sending back to Claude

        Args:
            model:          Claude model name.
            tools:          List of tool definitions (same format as Anthropic SDK).
            tool_executor:  Function that executes a tool: fn(name, input) -> result.
            messages:       Initial message list.
            task:           Human-readable task description for audit log.
            reasoning_trace: Agent reasoning for audit log.
            max_iterations: Safety limit on tool use rounds.
            **create_kwargs: Passed to messages.create().

        Returns:
            Final Message response from Claude.
        """
        msgs = list(messages)

        for _ in range(max_iterations):
            response = self.messages.create(
                model=model,
                tools=tools,
                messages=msgs,
                task=task,
                reasoning_trace=reasoning_trace,
                **create_kwargs,
            )

            if response.stop_reason != "tool_use":
                return response

            # Collect tool calls from response.
            tool_uses = [b for b in response.content if b.type == "tool_use"]
            tool_results = []

            for tool_use in tool_uses:
                # Resolve vault tokens in tool input before execution.
                resolved_input = self._interceptor.resolve_tool_input(
                    tool_use.name, tool_use.input, task=task
                )

                # Execute the tool with real values.
                raw_result = tool_executor(tool_use.name, resolved_input)

                # Vault sensitive content in result before sending back to Claude.
                clean_result = self._interceptor.scan_tool_result(
                    raw_result, tool_name=tool_use.name, task=task
                )
                if not isinstance(clean_result, str):
                    clean_result = json.dumps(clean_result)

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": clean_result,
                })

            # Append assistant response + tool results to message history.
            msgs.append({"role": "assistant", "content": response.content})
            msgs.append({"role": "user", "content": tool_results})

        return response


class _AkashaMessages:
    """Proxies anthropic.messages with vault interception."""

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
        Drop-in for anthropic.messages.create().

        Scans all message content for sensitive values before sending to Claude.
        Claude only ever sees vault:// tokens, never real sensitive data.
        """
        clean_messages = self._interceptor.scan_messages(messages, task=task)
        return self._client.messages.create(messages=clean_messages, **kwargs)
