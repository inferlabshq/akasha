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
    # secret.value now raises ValueError — the buffer behind it was zeroed

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

# CR, LF and NUL frame the HTTP request the Unix-socket transport writes by
# hand. There is no escape for them inside a header value, so they can only be
# refused.
_HEADER_FORBIDDEN = ("\r", "\n", "\x00")


class AkashaTransportError(httpx.TransportError):
    """The daemon's raw HTTP response could not be parsed."""


def _reject_header_control_chars(name: str, value: str) -> None:
    for ch in _HEADER_FORBIDDEN:
        if ch in name or ch in value:
            raise ValueError(
                "header %r carries a CR, LF or NUL byte — strip it before "
                "handing it to the SDK; those bytes frame the HTTP request and "
                "cannot be escaped" % name
            )


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
    A secret value held in a bytearray that is zeroed when `use()` exits.

    Unlike a Python str (immutable, possibly interned), a bytearray can be
    overwritten in place. On exit from a `vault.use()` block every byte of the
    buffer is set to zero and the object is marked spent: reading `.value`
    after that raises ValueError rather than returning zeros or stale text.

    What this does and does not buy you:

      * It clears the ONE copy the SDK owns — the internal bytearray.
      * `.value` decodes that buffer into a fresh immutable str on every read.
        Python cannot zero a str, so each read leaks a copy that survives until
        the garbage collector reclaims it, and the interpreter is free to have
        moved it first. Pass `secret.value` straight into the call that needs
        it; do not stash it in a variable, log it, or format it into a message.
      * It is not protection against a process that can read this process's
        memory, against swap, or against a core dump taken mid-block.

    Usage::

        with vault.use("vault://abc123", tool="stripe_charge") as secret:
            client.charge(secret.value)
        # secret.value now raises ValueError — the buffer behind it is zeroed
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
        ValueError: if api_key contains CR, LF or NUL. The Unix-socket
            transport writes the HTTP preamble itself, so those bytes in a key
            are not a malformed header — they are additional headers, or an
            additional request, chosen by whoever supplied the key.
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
        for ch in _HEADER_FORBIDDEN:
            if ch in api_key:
                raise ValueError(
                    "api_key carries a CR, LF or NUL byte — re-copy the key "
                    "printed by `akasha agent create`; the SDK writes it into a "
                    "raw HTTP header where those bytes would splice in requests "
                    "of the sender's choosing"
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


class _SocketReader:
    """Buffered reader over a connected socket, for framing an HTTP response."""

    def __init__(self, sock: socket.socket, buffered: bytes = b""):
        self._sock = sock
        self._buf = bytearray(buffered)
        self._eof = False
        self.bytes_seen = len(buffered)

    def _fill(self) -> bool:
        """Pull one more read from the socket. False once the peer is done."""
        if self._eof:
            return False
        chunk = self._sock.recv(65536)
        if not chunk:
            self._eof = True
            return False
        self._buf += chunk
        self.bytes_seen += len(chunk)
        return True

    def take(self, n: int) -> bytes:
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def read_exactly(self, n: int, what: str) -> bytes:
        while len(self._buf) < n:
            if not self._fill():
                raise AkashaTransportError(
                    "daemon closed the connection with %d of %d bytes of %s still "
                    "unsent — check `akasha status` and the daemon log for a crash "
                    "mid-response" % (len(self._buf), n, what)
                )
        return self.take(n)

    def read_line(self, what: str) -> bytes:
        """Read one CRLF-terminated line, without the CRLF."""
        while True:
            idx = self._buf.find(b"\r\n")
            if idx != -1:
                line = self.take(idx + 2)
                return line[:-2]
            if not self._fill():
                raise AkashaTransportError(
                    "daemon closed the connection part-way through %s — check "
                    "`akasha status` and the daemon log for a crash mid-response"
                    % what
                )

    def read_to_eof(self) -> bytes:
        while self._fill():
            pass
        return self.take(len(self._buf))


def _decode_chunked(reader: _SocketReader) -> bytes:
    body = bytearray()
    while True:
        line = reader.read_line("a chunk-size line")
        # RFC 7230 allows chunk extensions after a semicolon; the size is what
        # precedes it.
        size_field = line.split(b";", 1)[0].strip()
        # int(_, 16) alone would also accept "-5" and "1_0"; a chunk size is
        # plain hex digits and nothing else.
        if not size_field or not all(c in b"0123456789abcdefABCDEF" for c in size_field):
            raise AkashaTransportError(
                "daemon sent %r where a hex chunk size belongs — the response is "
                "not valid chunked HTTP; report it with the daemon version from "
                "`akasha version`" % size_field.decode("latin-1")[:40]
            )
        size = int(size_field, 16)
        if size == 0:
            break
        body += reader.read_exactly(size, "a chunk body")
        if reader.read_exactly(2, "a chunk terminator") != b"\r\n":
            raise AkashaTransportError(
                "daemon sent a chunk not terminated by CRLF — the response is not "
                "valid chunked HTTP; report it with the daemon version from "
                "`akasha version`"
            )
    # Trailer section, ended by a blank line. A daemon that hangs up right after
    # the terminating chunk has still delivered the whole body.
    try:
        while reader.read_line("the chunked trailer") != b"":
            pass
    except AkashaTransportError:
        pass
    return bytes(body)


class _UnixSocketTransport(httpx.BaseTransport):
    """httpx transport over a Unix domain socket."""

    def __init__(self, socket_path: str, headers_fn):
        self._socket_path = socket_path
        self._headers_fn = headers_fn

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)
        try:
            self._send(sock, request)
            return self._receive(sock)
        finally:
            sock.close()

    def _send(self, sock: socket.socket, request: httpx.Request) -> None:
        body = request.content
        # Merge SDK headers into the request.
        extra = self._headers_fn()
        header_lines = ""
        for k, v in extra.items():
            if k.lower() == "content-type":  # already set below
                continue
            _reject_header_control_chars(k, v)
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

    def _receive(self, sock: socket.socket) -> httpx.Response:
        reader = _SocketReader(sock)
        status_code, headers = self._read_head(reader)

        encoding = headers.get("transfer-encoding", "")
        if "chunked" in [t.strip().lower() for t in encoding.split(",")]:
            content = _decode_chunked(reader)
        elif "content-length" in headers:
            raw_length = headers["content-length"]
            # int() alone would also accept "-5" and "1_0", and str.isdigit()
            # would accept "\xb2"; a Content-Length is ASCII digits, nothing else.
            if not raw_length or not all(c in "0123456789" for c in raw_length):
                raise AkashaTransportError(
                    "daemon sent Content-Length: %r, which is not a number — the "
                    "response is not valid HTTP; report it with the daemon version "
                    "from `akasha version`" % raw_length[:40]
                )
            content = reader.read_exactly(int(raw_length), "the response body")
        else:
            content = reader.read_to_eof()

        return httpx.Response(status_code, content=content)

    def _read_head(self, reader: _SocketReader) -> tuple:
        """Read the status line and headers. Returns (status_code, headers)."""
        try:
            status_line = reader.read_line("the status line")
        except AkashaTransportError:
            if reader.bytes_seen == 0:
                raise AkashaTransportError(
                    "daemon accepted the connection but sent no response at all — "
                    "check that the daemon is running and healthy with "
                    "`akasha status`"
                ) from None
            raise

        parts = status_line.split(b" ")
        if len(parts) < 2 or not parts[0].upper().startswith(b"HTTP/"):
            raise AkashaTransportError(
                "daemon sent %r as its first line instead of an HTTP status line — "
                "check that %s is the Akasha daemon's socket and not another "
                "program's"
                % (status_line.decode("latin-1")[:80], self._socket_path)
            )
        raw_code = parts[1]
        # RFC 7230: exactly three digits. int() would also take "-5" and "1_0",
        # and httpx would then carry the nonsense forward as a status.
        if len(raw_code) != 3 or not all(c in b"0123456789" for c in raw_code):
            raise AkashaTransportError(
                "daemon sent %r where a three-digit HTTP status code belongs — "
                "check that %s is the Akasha daemon's socket and not another "
                "program's" % (raw_code.decode("latin-1")[:40], self._socket_path)
            )
        status_code = int(raw_code)

        headers = {}
        while True:
            line = reader.read_line("the response headers")
            if line == b"":
                return status_code, headers
            name, sep, value = line.decode("latin-1").partition(":")
            if not sep:
                raise AkashaTransportError(
                    "daemon sent a response header line with no colon (%r) — the "
                    "response is not valid HTTP; report it with the daemon version "
                    "from `akasha version`" % line.decode("latin-1")[:80]
                )
            headers[name.strip().lower()] = value.strip()
