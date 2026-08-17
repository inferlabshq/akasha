"""
Unit tests for the Akasha Python SDK.

These tests mock the daemon's HTTP responses with respx — no running
daemon required. The Unix socket transport is bypassed by pointing the
client at a plain HTTP base URL in tests.
"""

import json
import pytest
import httpx
import respx

from akasha import Akasha, WrapResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_client(base_url: str = "http://localhost:7743") -> Akasha:
    """Build an Akasha client that uses a plain HTTP transport (no socket)."""
    vault = Akasha.__new__(Akasha)
    vault.agent_id = "test-agent"
    vault.api_key = None
    vault.run_id = None
    vault._socket_path = "/nonexistent.sock"
    vault._http_port = 7743
    vault._timeout = 5.0
    vault._client = httpx.Client(base_url=base_url, timeout=5.0)
    return vault


# ---------------------------------------------------------------------------
# wrap()
# ---------------------------------------------------------------------------

@respx.mock
def test_wrap_sensitive():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200,
        json={
            "clean_content": "ssn is vault://abc12345",
            "vaulted": True,
            "token": "vault://abc12345",
            "category": "SSN",
            "risk": "critical",
        }
    ))
    v = make_client()
    r = v.wrap("lookup_account", "ssn is 429-21-0001")
    assert r.vaulted is True
    assert r.token == "vault://abc12345"
    assert r.category == "SSN"
    assert r.risk == "critical"
    assert "vault://abc12345" in r.clean_content


@respx.mock
def test_wrap_multiple_secrets():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200,
        json={
            "clean_content": "key vault://k ssn vault://s",
            "vaulted": True,
            "token": "vault://k",
            "category": "AWSAccessKey",
            "risk": "high",
            "tokens": ["vault://k", "vault://s"],
        }
    ))
    v = make_client()
    r = v.wrap("send", "key AKIAIOSFODNN7EXAMPLE ssn 429-21-0001")
    assert r.tokens == ["vault://k", "vault://s"]
    assert "vault://k" in r.clean_content and "vault://s" in r.clean_content


@respx.mock
def test_wrap_clean():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200,
        json={"clean_content": "hello world", "vaulted": False}
    ))
    v = make_client()
    r = v.wrap("get_weather", "hello world")
    assert r.vaulted is False
    assert r.token is None
    assert r.clean_content == "hello world"


@respx.mock
def test_wrap_sends_provenance():
    route = respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200,
        json={"clean_content": "x", "vaulted": False}
    ))
    v = make_client()
    v.wrap(
        "send_email",
        "x",
        task="Refund order #8821",
        reasoning_trace="User requested refund",
        triggered_by="user message",
    )
    sent = route.calls.last.request
    import json
    body = json.loads(sent.content)
    assert body["task"] == "Refund order #8821"
    assert body["reasoning_trace"] == "User requested refund"
    assert body["triggered_by"] == "user message"


# ---------------------------------------------------------------------------
# retrieve()
# ---------------------------------------------------------------------------

@respx.mock
def test_retrieve_direct():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "429-21-0001"}
    ))
    v = make_client()
    val = v.retrieve("vault://abc12345", requesting_tool="stripe_charge")
    assert val == "429-21-0001"


@respx.mock
def test_retrieve_via_grant():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "4111111111111111"}
    ))
    v = make_client()
    val = v.retrieve(grant_id="grt://xyz789abc", requesting_tool="charge_card")
    assert val == "4111111111111111"


def test_retrieve_no_args():
    v = make_client()
    with pytest.raises(ValueError):
        v.retrieve()


# ---------------------------------------------------------------------------
# grant()
# ---------------------------------------------------------------------------

@respx.mock
def test_grant():
    respx.post("http://localhost:7743/grant").mock(return_value=httpx.Response(
        200, json={"grant_id": "grt://xyz789abc"}
    ))
    v = make_client()
    gid = v.grant(
        "vault://abc12345",
        "payment-agent",
        allowed_tool="charge_card",
        task="Refund order #8821",
        ttl_seconds=300,
    )
    assert gid == "grt://xyz789abc"


# ---------------------------------------------------------------------------
# inspect() / status()
# ---------------------------------------------------------------------------

@respx.mock
def test_inspect():
    respx.get("http://localhost:7743/inspect").mock(return_value=httpx.Response(
        200,
        json={"token": "vault://abc12345", "category": "SSN", "risk": "critical"}
    ))
    v = make_client()
    entry = v.inspect("vault://abc12345")
    assert entry["category"] == "SSN"


@respx.mock
def test_use_context_manager():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "super-secret-value"}
    ))
    v = make_client()
    with v.use("vault://abc123", tool="stripe_charge", task="Charge order") as secret:
        assert secret.value == "super-secret-value"
        assert repr(secret) == "Secret(***)"
    # Zeroed after block exits
    assert secret._zeroed is True
    assert all(b == 0 for b in secret._buf)


@respx.mock
def test_use_zeroes_on_exception():
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "super-secret-value"}
    ))
    v = make_client()
    try:
        with v.use("vault://abc123", tool="stripe_charge") as secret:
            raise ValueError("something went wrong")
    except ValueError:
        pass
    # Must be zeroed even after exception
    assert secret._zeroed is True


def test_secret_raises_after_zero():
    from akasha.client import Secret
    s = Secret("my-secret")
    s._zero()
    try:
        _ = s.value
        assert False, "should have raised"
    except ValueError:
        pass


@respx.mock
def test_use_sets_tool_name():
    """SDK sets requesting_tool from the tool= arg — agent cannot override."""
    route = respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "secret"}
    ))
    v = make_client()
    with v.use("vault://abc123", tool="stripe_charge") as _:
        pass
    body = json.loads(route.calls.last.request.content)
    assert body["requesting_tool"] == "stripe_charge"


@respx.mock
def test_api_key_sent_in_header():
    route = respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "x", "vaulted": False}
    ))
    v = make_client()
    v.api_key = "agt_myagent_abc123"
    v.wrap("get_weather", "x")
    assert route.calls.last.request.headers.get("x-akasha-key") == "agt_myagent_abc123"


@respx.mock
def test_status():
    respx.get("http://localhost:7743/health").mock(return_value=httpx.Response(
        200,
        json={"status": "ok", "vault_total": 3, "vault_expired": 0}
    ))
    v = make_client()
    s = v.status()
    assert s["status"] == "ok"
    assert s["vault_total"] == 3


def test_api_key_is_required():
    """
    The daemon refuses unauthenticated callers, so constructing a keyless client
    is a mistake worth catching at the constructor rather than as a 401 on every
    later call.

    This is not merely a tightened argument check. Omitting the key used to be
    the PRIVILEGED path: the daemon read a missing key as the trusted local
    human, which is what allowed a revoked agent key to be traded for more
    access by simply not presenting it.
    """
    with pytest.raises(ValueError) as e:
        Akasha(agent_id="support-bot-v2")
    assert "api_key is required" in str(e.value)
    # The message should name the command that issues one.
    assert "akasha agent create support-bot-v2" in str(e.value)


def test_api_key_may_not_be_blank():
    with pytest.raises(ValueError):
        Akasha(agent_id="support-bot-v2", api_key="")
