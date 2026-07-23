"""
Tests for the LangChain AkashaCallback.

The callback's vault logic is exercised through a mocked daemon; langchain
itself is not required because BaseCallbackHandler falls back to `object`.
"""

import httpx
import respx

from akasha.client import Akasha
from akasha.integrations.langchain import AkashaCallback


def make_vault(base_url="http://localhost:7743") -> Akasha:
    v = Akasha.__new__(Akasha)
    v.agent_id = "lc-test"
    v.api_key = None
    v.run_id = None
    v._socket_path = "/nonexistent.sock"
    v._http_port = 7743
    v._timeout = 5.0
    v._client = httpx.Client(base_url=base_url, timeout=5.0)
    return v


def make_handler() -> AkashaCallback:
    # Bypass the langchain-not-installed guard by injecting a vault client.
    return AkashaCallback(agent_id="lc-test", vault_client=make_vault())


@respx.mock
def test_on_tool_end_vaults_output():
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "balance vault://tok1", "vaulted": True}
    ))
    h = make_handler()
    out = h.on_tool_end("balance $50,000", name="get_balance")
    assert "vault://" in out


@respx.mock
def test_guard_decorator_resolves_and_vaults():
    # resolve_text on input, scan_tool_result on output.
    respx.post("http://localhost:7743/retrieve").mock(return_value=httpx.Response(
        200, json={"value": "429-21-0001"}
    ))
    respx.post("http://localhost:7743/wrap").mock(return_value=httpx.Response(
        200, json={"clean_content": "ok vault://t2", "vaulted": True}
    ))
    h = make_handler()

    @h.guard("lookup_account")
    def lookup_account(ssn: str) -> str:
        # token should already be resolved to the real value here
        assert ssn == "429-21-0001"
        return "ok 429-21-0001"

    result = lookup_account("vault://abc123")
    assert "vault://" in result  # output vaulted


def test_import_guard_without_vault_client(monkeypatch):
    # When langchain is absent and no vault_client is given, construction
    # should raise a helpful ImportError.
    import akasha.integrations.langchain as lc
    monkeypatch.setattr(lc, "BaseCallbackHandler", object)
    try:
        lc.AkashaCallback(agent_id="x")
        assert False, "expected ImportError"
    except ImportError:
        pass
