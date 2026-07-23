"""
Shared vault interception logic for all LLM integrations.

The two core operations:

  scan_and_vault(text)
    → scans content for sensitive values via /wrap
    → replaces real values with vault:// tokens
    → returns clean text safe to send to any LLM

  resolve_tokens(text)
    → finds vault:// tokens in text
    → retrieves real values via /retrieve
    → returns text with tokens replaced by real values
    → used before executing tool calls

Both operations are fully audited.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from akasha.client import Akasha

# Matches vault://... tokens anywhere in a string.
_TOKEN_RE = re.compile(r"vault://[A-Za-z0-9_\-]+")


class VaultInterceptor:
    """
    Wraps an Akasha client with helper methods for LLM integration.

    All scanning and resolution goes through the running Akasha daemon —
    no vault logic lives here.
    """

    def __init__(self, vault: Akasha, run_id: Optional[str] = None):
        self.vault = vault
        self.run_id = run_id

    # ------------------------------------------------------------------
    # Outbound: scan content before sending to LLM
    # ------------------------------------------------------------------

    def scan_text(self, text: str, tool_name: str = "", task: str = "",
                  reasoning_trace: str = "") -> str:
        """
        Scan a string for sensitive content and replace with vault tokens.
        Returns the clean string safe to send to the LLM.
        """
        if not text or not text.strip():
            return text
        result = self.vault.wrap(
            tool_name=tool_name or "llm_message",
            content=text,
            task=task,
            reasoning_trace=reasoning_trace,
        )
        return result.clean_content

    def scan_messages(self, messages: list[dict], task: str = "") -> list[dict]:
        """
        Scan all message content in a message list.
        Handles both string content and structured content blocks.
        Returns a new list with sensitive values vaulted.
        """
        clean = []
        for msg in messages:
            clean.append(self._scan_message(msg, task))
        return clean

    def _scan_message(self, msg: dict, task: str) -> dict:
        msg = dict(msg)
        content = msg.get("content")
        role = msg.get("role", "")

        if isinstance(content, str):
            msg["content"] = self.scan_text(content, task=task)
        elif isinstance(content, list):
            msg["content"] = [self._scan_block(b, task, role) for b in content]
        return msg

    def _scan_block(self, block: Any, task: str, role: str) -> Any:
        if not isinstance(block, dict):
            return block
        block = dict(block)
        btype = block.get("type", "")

        # Plain text block.
        if btype == "text" and isinstance(block.get("text"), str):
            block["text"] = self.scan_text(block["text"], task=task)

        # Tool result — scan the content before it goes back to the LLM.
        elif btype == "tool_result":
            inner = block.get("content")
            if isinstance(inner, str):
                block["content"] = self.scan_text(
                    inner, tool_name="tool_result", task=task)
            elif isinstance(inner, list):
                block["content"] = [self._scan_block(b, task, role) for b in inner]

        return block

    # ------------------------------------------------------------------
    # Inbound: resolve vault tokens before executing tool calls
    # ------------------------------------------------------------------

    def resolve_text(self, text: str, tool_name: str = "", task: str = "") -> str:
        """
        Replace vault:// tokens in text with their real values.
        Used to prepare tool call arguments before execution.
        """
        tokens = _TOKEN_RE.findall(text)
        for token in set(tokens):
            try:
                real = self.vault.retrieve(
                    token,
                    requesting_tool=tool_name or "tool_execution",
                    task=task,
                )
                text = text.replace(token, real)
            except Exception:
                # Token not found or expired — leave as-is.
                pass
        return text

    def resolve_tool_input(self, tool_name: str, input_data: Any,
                           task: str = "") -> Any:
        """
        Resolve vault tokens in tool call input (dict or string).
        Returns input safe to pass to the actual tool function.
        """
        if isinstance(input_data, str):
            return self.resolve_text(input_data, tool_name=tool_name, task=task)
        elif isinstance(input_data, dict):
            return {
                k: self.resolve_tool_input(tool_name, v, task)
                for k, v in input_data.items()
            }
        elif isinstance(input_data, list):
            return [self.resolve_tool_input(tool_name, v, task) for v in input_data]
        return input_data

    def resolve_json_arguments(self, arguments_str: str, tool_name: str,
                                task: str = "") -> str:
        """
        Resolve vault tokens inside a JSON-encoded arguments string
        (OpenAI tool call format).
        """
        try:
            parsed = json.loads(arguments_str)
            resolved = self.resolve_tool_input(tool_name, parsed, task)
            return json.dumps(resolved)
        except json.JSONDecodeError:
            # Not valid JSON — resolve as raw text.
            return self.resolve_text(arguments_str, tool_name=tool_name, task=task)

    # ------------------------------------------------------------------
    # Scan tool results before sending back to LLM
    # ------------------------------------------------------------------

    def scan_tool_result(self, result: Any, tool_name: str = "",
                         task: str = "") -> Any:
        """
        Scan a tool execution result for sensitive content.
        Returns the result with any sensitive values vaulted.
        """
        if isinstance(result, str):
            return self.scan_text(result, tool_name=tool_name, task=task)
        elif isinstance(result, dict):
            return {k: self.scan_tool_result(v, tool_name, task)
                    for k, v in result.items()}
        elif isinstance(result, list):
            return [self.scan_tool_result(v, tool_name, task) for v in result]
        return result
