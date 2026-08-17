"""
Tests for the raw Unix-socket transport.

Every other test in this suite builds the client with ``Akasha.__new__`` and a
plain httpx transport, so ``_UnixSocketTransport`` is never constructed and the
hand-written HTTP framing is never exercised. These tests do the opposite: they
bind a real Unix socket, serve canned bytes over it, and drive the real client
end to end so the framing itself is under test.
"""

import json
import os
import shutil
import socket
import tempfile
import threading

import pytest

from akasha import Akasha
from akasha.client import AkashaTransportError


# ---------------------------------------------------------------------------
# A Unix-socket server that replays canned response bytes
# ---------------------------------------------------------------------------

class CannedSocketServer:
    """Serves one canned raw HTTP response per connection."""

    def __init__(self, response: bytes):
        # Not tmp_path: a pytest tmp_path plus a filename can exceed the ~104
        # byte sun_path limit on macOS, and bind() then fails for reasons that
        # have nothing to do with the test.
        self.dir = tempfile.mkdtemp(prefix="ak")
        self.path = os.path.join(self.dir, "d.sock")
        self.response = response
        self.requests = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        self._sock.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                self.requests.append(_read_request(conn))
                conn.sendall(self.response)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self._sock.close()
        self._thread.join(timeout=2)
        shutil.rmtree(self.dir, ignore_errors=True)


def _read_request(conn: socket.socket) -> bytes:
    """Read one request: head, then Content-Length bytes of body."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return buf
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


@pytest.fixture
def serve():
    servers = []

    def _serve(response: bytes) -> CannedSocketServer:
        server = CannedSocketServer(response)
        servers.append(server)
        return server

    yield _serve
    for server in servers:
        server.close()


def client_for(server: CannedSocketServer, api_key: str = "agt_test_abc123") -> Akasha:
    """A REAL Akasha client wired to the canned server's socket."""
    return Akasha(agent_id="test-agent", api_key=api_key, socket_path=server.path)


# ---------------------------------------------------------------------------
# Response framing
# ---------------------------------------------------------------------------

def chunked(body: bytes, chunk_size: int = 1024, headers: bytes = b"") -> bytes:
    out = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n" + headers + b"\r\n"
    )
    for i in range(0, len(body), chunk_size):
        piece = body[i:i + chunk_size]
        out += b"%x\r\n" % len(piece) + piece + b"\r\n"
    return out + b"0\r\n\r\n"


def with_content_length(body: bytes) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body)
    ) + body


# A stand-in for the case that actually breaks: Go's net/http switches to
# chunked whenever a handler writes without setting Content-Length, which is
# every response over roughly 2KB — including most SSH private keys.
BIG_SECRET = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + ("b3BlbnNzaC1rZXktdjEA" * 200)


def test_chunked_response_over_2kb_round_trips(serve):
    """GUARANTEE: a chunked body arrives intact, with no framing left in it.

    The transport used to split on the first blank line and hand everything
    after it to json as the body, chunk-size lines and all.
    """
    body = json.dumps({"value": BIG_SECRET}).encode()
    assert len(body) > 2048, "this case only bites above the chunking threshold"
    server = serve(chunked(body))

    with client_for(server) as vault:
        assert vault.retrieve("vault://abc123", requesting_tool="ssh") == BIG_SECRET


def test_chunked_response_with_trailer_round_trips(serve):
    body = json.dumps({"value": BIG_SECRET}).encode()
    response = chunked(body, headers=b"Trailer: X-Akasha-Audit\r\n")
    # Replace the bare terminator with one carrying a trailer field.
    assert response.endswith(b"0\r\n\r\n")
    response = response[:-2] + b"X-Akasha-Audit: evt_123\r\n\r\n"
    server = serve(response)

    with client_for(server) as vault:
        assert vault.retrieve("vault://abc123", requesting_tool="ssh") == BIG_SECRET


def test_chunked_response_arriving_in_dribs(serve):
    """The body is complete when the terminating chunk lands, not when the
    socket closes, and chunk boundaries need not align with recv() boundaries."""
    body = json.dumps({"value": BIG_SECRET}).encode()
    server = serve(chunked(body, chunk_size=7))

    with client_for(server) as vault:
        assert vault.retrieve("vault://abc123", requesting_tool="ssh") == BIG_SECRET


def test_content_length_response_round_trips(serve):
    body = json.dumps({"clean_content": "ssn is vault://abc", "vaulted": True,
                       "token": "vault://abc"}).encode()
    server = serve(with_content_length(body))

    with client_for(server) as vault:
        result = vault.wrap("lookup_account", "ssn is 429-21-0001")
    assert result.vaulted is True
    assert result.token == "vault://abc"


def test_response_without_framing_headers_reads_to_close(serve):
    body = json.dumps({"status": "ok", "vault_total": 3}).encode()
    server = serve(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)

    with client_for(server) as vault:
        assert vault.status()["vault_total"] == 3


def test_non_200_status_is_surfaced(serve):
    body = b'{"error":"unknown agent key"}'
    server = serve(
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    )

    with client_for(server) as vault:
        with pytest.raises(Exception) as e:
            vault.status()
    assert "401" in str(e.value)


# ---------------------------------------------------------------------------
# Malformed responses raise, rather than corrupting
# ---------------------------------------------------------------------------

def test_empty_response_raises_clear_error(serve):
    """A daemon that accepts and hangs up used to raise IndexError on the
    status line, naming nothing the caller could act on."""
    server = serve(b"")

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "no response" in str(e.value)


def test_headerless_response_raises_clear_error(serve):
    """No blank line at all: the old code sliced with header_end == -1, which
    silently produced a body built from the tail of the header block."""
    server = serve(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "response headers" in str(e.value)


def test_truncated_body_raises_clear_error(serve):
    body = b'{"status":"ok","vault_total":3}'
    server = serve(
        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body[:10]
    )

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "10 of %d bytes" % len(body) in str(e.value)


def test_truncated_chunked_body_raises_clear_error(serve):
    server = serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\nshort")

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError):
            vault.status()


def test_garbage_status_line_raises_clear_error(serve):
    server = serve(b"NOT-HTTP hello\r\n\r\n")

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "status line" in str(e.value)


@pytest.mark.parametrize("code", [b"OK", b"-5", b"1_0", b"20", b"2000"])
def test_non_numeric_status_code_raises_clear_error(serve, code):
    server = serve(b"HTTP/1.1 " + code + b" OK\r\nContent-Length: 0\r\n\r\n")

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "status code" in str(e.value)


@pytest.mark.parametrize("length", [b"many", b"-5", b"1_0", b"", b"\xb2"])
def test_non_numeric_content_length_raises_clear_error(serve, length):
    """int() would accept "-5" and "1_0" and str.isdigit() would accept "\\xb2";
    a negative length in particular reads zero bytes and returns an empty body."""
    server = serve(b"HTTP/1.1 200 OK\r\nContent-Length: " + length + b"\r\n\r\n{}")

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "Content-Length" in str(e.value)


@pytest.mark.parametrize("size", [b"-5", b"1_0", b"zz", b""])
def test_non_hex_chunk_size_raises_clear_error(serve, size):
    server = serve(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + size + b"\r\n{}\r\n0\r\n\r\n"
    )

    with client_for(server) as vault:
        with pytest.raises(AkashaTransportError) as e:
            vault.status()
    assert "chunk size" in str(e.value)


def test_chunk_extensions_are_ignored(serve):
    body = b'{"status":"ok","vault_total":3}'
    server = serve(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"%x;name=value\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    )

    with client_for(server) as vault:
        assert vault.status()["vault_total"] == 3


# ---------------------------------------------------------------------------
# Header injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["agt_a_x\r\nX-Evil: 1", "agt_a_x\n", "agt_a_x\r", "agt_a_\x00x"])
def test_api_key_with_control_characters_is_rejected_at_construction(bad):
    """GUARANTEE: CR, LF and NUL never reach the hand-written HTTP preamble.

    The transport interpolates the key into the request head, so a key
    carrying CRLF appends headers of the sender's choosing, and a doubled CRLF
    appends an entire second request.
    """
    with pytest.raises(ValueError) as e:
        Akasha(agent_id="a", api_key=bad)
    assert "api_key" in str(e.value)


def test_transport_refuses_to_interpolate_an_injected_header(serve):
    """The constructor is not the only way a value reaches the preamble, so the
    interpolation point refuses the bytes too."""
    server = serve(with_content_length(b"{}"))

    with client_for(server) as vault:
        vault.api_key = "agt_a_x\r\nX-Akasha-Bypass: 1"
        with pytest.raises(ValueError) as e:
            vault.status()
    assert "X-Akasha-Key" in str(e.value)
    # The transport connects before it builds the preamble, so the server may
    # well have accepted an empty connection. What must not happen is bytes.
    assert all(r == b"" for r in server.requests), (
        "no byte of the poisoned request may reach the socket, got %r"
        % server.requests
    )


def test_wellformed_api_key_is_sent_over_the_socket(serve):
    server = serve(with_content_length(b'{"status":"ok"}'))

    with client_for(server, api_key="agt_test_abc123") as vault:
        vault.status()

    assert b"X-Akasha-Key: agt_test_abc123\r\n" in server.requests[0]
