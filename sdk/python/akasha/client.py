"""
Akasha Python thin client.

Talks to the Akasha Go daemon over a Unix socket (default) or local HTTP
fallback on port 7743. No vault logic lives here — this is a dumb pipe.

Usage::

    from akasha import Akasha

    vault = Akasha(agent_id="support-bot-v2", api_key="agt_support-bot-v2_...")

    # Intercept a tool call before it runs:
    result = vault.wrap(
        tool_name="send_email",
        content="Sending invoice to alice@example.com, card 4111111111111111",
        task="Process refund for order #8821",
        reasoning_trace="User requested refund. Order #8821 verified. Initiating.",
        triggered_by="user message: 'I want my money back'",
    )
    # result.clean_content  → "... vault://abc12345 ..."

    # use() context manager — tool name is set by SDK, secret zeroed on exit:
    with vault.use(result.token, tool="stripe_charge") as secret:
        stripe.charge(secret.value)
    # secret.value is now all zeros

    # A2A cross-agent delegation:
    grant_id = vault.grant(
        token=result.token,
        grantee_agent="payment-bot-v1",
        allowed_tool="stripe_charge",
        task="Charge refund for order #8821",
        ttl_seconds=300,
    )
"""

from __future__ import annotations

import os
import socket
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Generator, Optional

import httpx

_DEFAULT_SOCKET = os.path.expanduser("~/.akasha/akasha.sock")
_DEFAULT_HTTP_PORT = 7743


@dataclass
class WrapResult:
    clean_content: str
    vaulted: bool
    token: Optional[str] = None
    category: Optional[str] = None
    risk: Optional[str] = None
    # Every vaulted secret's token, in the order they appear in clean_content.
    # token/category/risk describe the highest-risk one, for the common
    # single-secret case.
    tokens: list = field(default_factory=list)


@dataclass
class GrantResult:
    grant_id: str


class Secret:
    """
    A mutable secret value backed by a bytearray.

    Unlike Python strings (immutable, interned), bytearray memory can be
    zeroed after use. On exit from a `vault.use()` block the buffer is
    overwritten with zeros so the plaintext doesn't linger in heap memory.

    Usage::

        with vault.use("vault://abc123", tool="stripe_charge") as secret:
            client.charge(secret.value)
        # secret.value is now "\\x00\\x00..." — zeroed
    """

    def __init__(self, value: str):
        self._buf = bytearray(value.encode("utf-8"))
        self._zeroed = False

    @property
    def value(self) -> str:
        if self._zeroed:
            raise ValueError("Secret has been zeroed — cannot read after use() block exits")
        return self._buf.decode("utf-8")

    def _zero(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._zeroed = True

    def __repr__(self) -> str:
        return "Secret(***)"

    def __str__(self) -> str:
        return self.value


class Akasha:
    """
    Thin client for the Akasha daemon.

    Args:
        agent_id:    Identifier for this agent (e.g. "support-bot-v2").
        api_key:     Agent API key issued by `akasha agent create`. REQUIRED —
                     the daemon refuses unauthenticated callers. It verifies the
                     key and uses the server-side agent_id, so the self-reported
                     agent_id above is advisory and is ignored wherever the two
                     disagree.

                     This was previously optional, and omitting it was not just
                     permitted but *privileged*: the daemon read a missing key
                     as the trusted local human, so a revoked key could be
                     traded for MORE access by not sending it. The keyless path
                     was removed; see docs/design/same-user-identity.md.
        socket_path: Path to the Unix socket. Defaults to ~/.akasha/akasha.sock.
        http_port:   HTTP fallback port. Defaults to 7743.
        run_id:      Optional run ID propagated into every audit event.
        timeout:     Request timeout in seconds. Defaults to 5.

    Raises:
        ValueError: if api_key is missing. Failing here, rather than letting
            every call return 401, keeps the cause next to the mistake.
    """

    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        socket_path: str = _DEFAULT_SOCKET,
        http_port: int = _DEFAULT_HTTP_PORT,
        run_id: Optional[str] = None,
        timeout: float = 5.0,
    ):
        if not api_key:
            raise ValueError(
                "api_key is required: the Akasha daemon refuses unauthenticated callers. "
                "Issue one with `akasha agent create %s`. "
                "(Omitting it used to work, and was treated as the local human — that "
                "inversion is what let a revoked key regain access by presenting less.)"
                % (agent_id or "<agent-id>")
            )
        self.agent_id = agent_id
        self.api_key = api_key
        self.run_id = run_id
        self._socket_path = socket_path
        self._http_port = http_port
        self._timeout = timeout
        self._client = self._make_client()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def wrap(
        self,
        tool_name: str,
        content: str,
        *,
        task: str = "",
        reasoning_trace: str = "",
        triggered_by: str = "",
    ) -> WrapResult:
        """
        Classify *content* and vault any sensitive values found.

        Args:
            tool_name:       The tool about to be called (e.g. "send_email").
            content:         The full input string to scan.
            task:            Human-readable description of what the agent is doing.
            reasoning_trace: The agent's reasoning at this moment.
            triggered_by:    What caused this tool call (e.g. a user message).

        Returns:
            WrapResult with clean_content, vaulted flag, and optional token/category/risk.
        """
        payload = {
            "agent_id": self.agent_id,
            "tool_name": tool_name,
            "content": content,
            "task": task,
            "reasoning_trace": reasoning_trace,
            "triggered_by": triggered_by,
        }
        if self.run_id:
            payload["run_id"] = self.run_id

        data = self._post("/wrap", payload)
        return WrapResult(
            clean_content=data["clean_content"],
            vaulted=data.get("vaulted", False),
            token=data.get("token"),
            category=data.get("category"),
            risk=data.get("risk"),
            tokens=data.get("tokens") or [],
        )

    @contextmanager
    def use(
        self,
        token: str,
        *,
        tool: str,
        task: str = "",
        reasoning_trace: str = "",
    ) -> Generator[Secret, None, None]:
        """
        Retrieve a vaulted secret and yield it as a zeroing Secret object.

        The tool name is set by the SDK at the call site — the agent cannot
        override it. The secret is zeroed when the block exits, whether
        normally or via exception.

        Usage::

            with vault.use("vault://abc123", tool="stripe_charge",
                           task="Charge refund order #8821") as secret:
                stripe.charge(secret.value)
            # secret zeroed here

        Args:
            token:          vault:// token to retrieve.
            tool:           Name of the tool that will use the secret.
                            Recorded in the audit log as requesting_tool.
            task:           Human-readable task description for audit.
            reasoning_trace: Agent reasoning at point of retrieval.
        """
        payload = {
            "token": token,
            "agent_id": self.agent_id,
            "requesting_tool": tool,   # set by SDK — agent cannot override
            "task": task,
            "reasoning_trace": reasoning_trace,
        }
        if self.run_id:
            payload["run_id"] = self.run_id

        data = self._post("/retrieve", payload)
        secret = Secret(data["value"])
        try:
            yield secret
        finally:
            secret._zero()

    def retrieve(
        self,
        token: Optional[str] = None,
        *,
        grant_id: Optional[str] = None,
        requesting_tool: str = "",
        task: str = "",
    ) -> str:
        """
        Retrieve the real value for a vault token (raw string, not zeroed).

        Prefer `use()` for tool calls — it enforces tool name and zeros on exit.
        Use `retrieve()` only when you need the raw value outside a tool context.
        """
        payload: dict = {
            "agent_id": self.agent_id,
            "requesting_tool": requesting_tool,
            "task": task,
        }
        if grant_id:
            payload["grant_id"] = grant_id
        elif token:
            payload["token"] = token
        else:
            raise ValueError("Provide either token or grant_id")

        data = self._post("/retrieve", payload)
        return data["value"]

    def grant(
        self,
        token: str,
        grantee_agent: str,
        *,
        allowed_tool: str = "",
        task: str = "",
        ttl_seconds: int = 0,
    ) -> str:
        """
        Create an A2A delegation grant. Returns a grt:// grant ID.
        """
        payload = {
            "token": token,
            "grantor_agent": self.agent_id,
            "grantee_agent": grantee_agent,
            "allowed_tool": allowed_tool,
            "task": task,
            "ttl_seconds": ttl_seconds,
        }
        data = self._post("/grant", payload)
        return data["grant_id"]

    def inspect(self, token: str) -> dict:
        """Return vault metadata for a token (no decryption)."""
        return self._get("/inspect", {"token": token})

    def inspect_grant(self, grant_id: str) -> dict:
        """Return grant metadata."""
        return self._get("/inspect", {"grant_id": grant_id})

    def status(self) -> dict:
        """Return daemon health and vault statistics."""
        return self._get("/health", {})

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Akasha":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        """Build request headers, including API key if configured."""
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-Akasha-Key"] = self.api_key
        return h

    def _make_client(self) -> httpx.Client:
        if os.path.exists(self._socket_path):
            transport = _UnixSocketTransport(self._socket_path, self._headers)
            return httpx.Client(
                transport=transport,
                base_url="http://akasha",
                timeout=self._timeout,
            )
        return httpx.Client(
            base_url=f"http://127.0.0.1:{self._http_port}",
            timeout=self._timeout,
            headers=self._headers(),
        )

    def _post(self, path: str, payload: dict) -> dict:
        try:
            resp = self._client.post(path, json=payload, headers=self._headers())
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError:
            self._client = self._make_client()
            resp = self._client.post(path, json=payload, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def _get(self, path: str, params: dict) -> dict:
        try:
            resp = self._client.get(path, params=params, headers=self._headers())
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError:
            self._client = self._make_client()
            resp = self._client.get(path, params=params, headers=self._headers())
            resp.raise_for_status()
            return resp.json()


class _UnixSocketTransport(httpx.BaseTransport):
    """httpx transport over a Unix domain socket."""

    def __init__(self, socket_path: str, headers_fn):
        self._socket_path = socket_path
        self._headers_fn = headers_fn

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)

        body = request.content
        # Merge SDK headers into the request.
        extra = self._headers_fn()
        header_lines = ""
        for k, v in extra.items():
            if k.lower() != "content-type":  # already set below
                header_lines += f"{k}: {v}\r\n"

        headers = (
            f"{request.method} {request.url.raw_path.decode()} HTTP/1.1\r\n"
            f"Host: akasha\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"{header_lines}"
            f"\r\n"
        )
        sock.sendall(headers.encode() + body)

        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()

        raw = b"".join(chunks)
        header_end = raw.find(b"\r\n\r\n")
        header_bytes = raw[:header_end].decode()
        response_body = raw[header_end + 4:]
        status_code = int(header_bytes.splitlines()[0].split(" ")[1])
        return httpx.Response(status_code, content=response_body)
