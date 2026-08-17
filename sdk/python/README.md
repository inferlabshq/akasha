# akasha-py

Python client for [Akasha](https://github.com/inferlabshq/akasha), a local vault
daemon that keeps secrets out of your AI agent's context window.

Your agent sends a tool call's text through `wrap()`. Anything sensitive in it —
API keys, card numbers, SSNs, private keys — is stored in the local vault and
replaced with a `vault://` token, so the model only ever sees the token. When the
tool actually needs the real value, `use()` fetches it, hands it to the call, and
zeroes its copy on the way out. Every wrap and every retrieval is written to a
local audit log with the tool name, task and reasoning that asked for it.

This package is a thin client. No vault logic lives here — it is a pipe to the
daemon over a Unix socket at `~/.akasha/akasha.sock`, falling back to
`127.0.0.1:7743`.

## Install

The daemon is the prerequisite; the SDK talks to nothing without it.

```sh
curl -sSL https://getakasha.dev/install | sh   # installs the akasha daemon
```

Then the client, from a checkout of the repo:

```sh
pip install ./sdk/python
```

Optional extras `anthropic`, `openai` and `all` pull in the matching provider SDK
for the drop-in wrappers in `akasha.integrations`.

## An API key is required

The daemon refuses unauthenticated callers. Mint a key for each agent:

```sh
akasha agent create support-bot-v2
```

The key is printed once and never stored — keep it out of source control and pass
it in from the environment. Constructing a client without one raises `ValueError`
immediately rather than failing as a 401 on every later call.

```python
import os
from akasha import Akasha

vault = Akasha(
    agent_id="support-bot-v2",
    api_key=os.environ["AKASHA_API_KEY"],
)
```

The daemon verifies the key and uses the `agent_id` bound to it server-side; the
`agent_id` argument is advisory and is ignored wherever the two disagree.

## Usage

```python
result = vault.wrap(
    tool_name="stripe_charge",
    content="Refund the card 4111111111111111",
    task="Process refund for order #8821",
    reasoning_trace="User requested refund. Order #8821 verified.",
    triggered_by="user message: 'I want my money back'",
)

result.clean_content  # "Refund the card vault://abc12345" — safe to send to the model
result.vaulted        # True
result.token          # "vault://abc12345"

with vault.use(result.token, tool="stripe_charge", task="Refund order #8821") as secret:
    stripe.Refund.create(payment_method=secret.value)
# secret.value now raises ValueError — the buffer behind it has been zeroed
```

`use()` sets the tool name at the call site, so the agent cannot claim a different
one in the audit log. Pass `secret.value` straight into the call that needs it:
each read decodes a fresh immutable `str` that Python cannot zero, so the zeroing
guarantee covers only the buffer the SDK owns.

To hand a secret to a second agent without either one seeing it, `grant()` issues
a scoped, expiring `grt://` delegation:

```python
grant_id = vault.grant(
    token=result.token,
    grantee_agent="payment-bot-v1",
    allowed_tool="stripe_charge",
    ttl_seconds=300,
)
```

## Status: alpha

Version 0.1.0, and the interface is not frozen — expect breaking changes on minor
version bumps until 1.0. Akasha reduces a secret's exposure; it does not eliminate
it. Redaction is pattern- and classifier-based, so it will miss secrets that look
like ordinary text, and any value that reaches a tool call is plaintext in this
process's memory for the duration. Treat it as defence in depth, not as a reason
to relax key rotation or least privilege.

Bugs and gaps: <https://github.com/inferlabshq/akasha/issues>.
