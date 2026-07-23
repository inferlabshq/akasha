"""
Akasha integration for LangChain.

LangChain exposes a callback interface (`BaseCallbackHandler`) that fires
around every tool invocation — the natural interception point. AkashaCallback
sits there and:

  - on_tool_start: resolves vault:// tokens in the tool input before the tool
    runs, so a tool that receives a token gets the real value.
  - on_tool_end:   scans the tool's output and vaults any sensitive values
    before they flow back into the chain / LLM context.

Usage::

    from akasha.integrations.langchain import AkashaCallback

    handler = AkashaCallback(agent_id="research-bot", api_key="agt_...")

    # Pass to any chain, agent, or tool call:
    result = agent.invoke(
        {"input": "..."},
        config={"callbacks": [handler]},
    )

The handler talks to the local Akasha daemon via the same thin client the rest
of the SDK uses — no vault logic lives here.
"""

from __future__ import annotations

from typing import Any, Optional

from akasha.client import Akasha
from .base import VaultInterceptor

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:  # pragma: no cover - exercised only without langchain
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # older layout
    except ImportError:
        BaseCallbackHandler = object  # allow import; raise on construction


class AkashaCallback(BaseCallbackHandler):
    """
    LangChain callback that routes tool I/O through the Akasha vault.

    Args:
        agent_id:    Akasha agent identifier (appears in the audit log).
        api_key:     Akasha agent API key (agt_...). Optional but recommended.
        task:        Default task description recorded with each event.
        vault_client: Pre-built Akasha client (mainly for testing).
    """

    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        task: str = "",
        vault_client: Optional[Akasha] = None,
    ):
        # Require langchain for real use, but allow construction with an
        # injected vault_client (test / embedding scenarios).
        if BaseCallbackHandler is object and vault_client is None:
            raise ImportError(
                "langchain is not installed. Run: pip install langchain-core"
            )
        if vault_client is not None:
            self._vault = vault_client
        else:
            kwargs: dict = {"agent_id": agent_id}
            if api_key:
                kwargs["api_key"] = api_key
            self._vault = Akasha(**kwargs)
        self._ic = VaultInterceptor(self._vault)
        self._task = task

    # ------------------------------------------------------------------
    # Tool lifecycle hooks
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict,
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Resolve vault tokens in the tool input before the tool runs."""
        tool_name = (serialized or {}).get("name", "tool")
        resolved = self._ic.resolve_text(input_str, tool_name=tool_name, task=self._task)
        # LangChain reads the (possibly mutated) input from this dict in newer
        # versions; mutating in place is the supported way to rewrite input.
        if "inputs" in kwargs and isinstance(kwargs["inputs"], dict):
            for k, v in list(kwargs["inputs"].items()):
                if isinstance(v, str):
                    kwargs["inputs"][k] = self._ic.resolve_text(
                        v, tool_name=tool_name, task=self._task
                    )
        self._last_resolved = resolved

    def on_tool_end(self, output: Any, **kwargs: Any) -> Any:
        """Vault sensitive values in the tool output before it re-enters context."""
        tool_name = kwargs.get("name", "tool")
        return self._ic.scan_tool_result(output, tool_name=tool_name, task=self._task)

    # ------------------------------------------------------------------
    # Convenience: wrap a plain callable as an Akasha-guarded tool
    # ------------------------------------------------------------------

    def guard(self, tool_name: str):
        """
        Decorator that wraps a tool function so its input tokens are resolved
        and its output is vaulted — for code paths outside the callback flow.

            @handler.guard("lookup_account")
            def lookup_account(ssn: str) -> dict: ...
        """
        def deco(fn):
            def wrapped(*args, **kw):
                args = tuple(
                    self._ic.resolve_text(a, tool_name=tool_name, task=self._task)
                    if isinstance(a, str) else a
                    for a in args
                )
                out = fn(*args, **kw)
                return self._ic.scan_tool_result(out, tool_name=tool_name, task=self._task)
            wrapped.__name__ = getattr(fn, "__name__", tool_name)
            return wrapped
        return deco
