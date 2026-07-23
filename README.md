# Akasha

**A local vault for AI agents.** Akasha automatically detects and captures sensitive data from agent tool calls before it can leak — replacing real values with `vault://` tokens — and maintains a full audit trail of everything agents touched.

Named after the Hindu concept of the cosmic ether that records every event in the universe.

**Core trust guarantee: sensitive data never leaves the machine.**

> **Status: alpha.** Pre-1.0 — don't use it to protect secrets you can't rotate.
> Read the [Threat Model](docs/THREATMODEL.md) and [Security Policy](SECURITY.md).

**New here?** → [Getting Started](docs/getting-started.md) · [Write a Plugin](docs/writing-a-plugin.md) · [Plugin Format](docs/PLUGIN_FORMAT.md)

---

## Quick Start

```bash
curl -sSL https://getakasha.dev/install | sh   # or: bash install.sh from a checkout
akasha setup
```

`akasha setup` does everything in one shot:
- Registers the daemon as a login service (auto-starts on boot)
- **Scans your machine and vaults what it finds** — AWS profiles, SSH keys, Git tokens
- Offers a passphrase-protected key backup (so you can recover if the OS keychain is lost)
- Writes the MCP config for Claude Code and prints SDK snippets for other agents

```
Scanning for credentials...
  ✓ AWS default profile    → vaulted
  ✓ AWS pk-website profile → vaulted
  ✓ SSH key id_ed25519     → vaulted
Claude Code ready — restart it.
```

The vault lives at `~/.akasha/vault.db`, encrypted with **XChaCha20-Poly1305**. The
key is wrapped with **ML-KEM-768** (post-quantum) and stored in your OS keychain —
never on disk. The cloud audit layer (paid) only ever receives tokens and metadata.

---

## Use it from Claude Code (zero code)

After `akasha setup`, Claude Code (and any MCP client — Codex, Cursor, VS Code Copilot) gets these
tools natively. The headline one for credentials:

```
vault_assume(provider="aws", profile="default")
→ { "env": { "AWS_SHARED_CREDENTIALS_FILE": "/Users/.../sessions/aws-default.creds",
             "AWS_PROFILE": "default" },
    "expires_at": "..." }
```

The agent sets the returned env vars and runs `aws ...` normally. **The agent never
receives the raw secret** — only a short-lived (0600, 1h TTL) file handle. There is
no unsafe way to use a credential the agent never holds. Every assume is audited.

These credential files are written to **RAM-backed storage** (tmpfs on Linux, a
RAM disk on macOS) — they never touch the SSD, and vanish on reboot. For secrets
with no native file format, the `env:` provider delivers them as environment
variables instead (see *Store a secret discovery didn't find* below).

Other MCP tools: `vault_wrap`, `vault_store`, `vault_retrieve`, `vault_grant`,
`vault_inspect`, `vault_status`.

## Be the vault the *other* MCP servers run on

MCP servers are siblings — your client multiplexes between them and they don't
see each other's traffic, so Akasha can't intercept what a GitHub or Postgres
server does. What it *can* do is supply their credentials, so those secrets
aren't sitting in plaintext in your MCP config. `akasha exec` draws a vaulted
credential into a process, runs it, and cleans up on exit.

When the provider speaks a credential protocol — `git`, or an AWS
`credential_process` — exec wires the tool to call back through Akasha **per
operation**, so the raw secret never lands in the environment at all:

```bash
akasha exec --assume github:default -- git clone https://github.com/org/repo.git
akasha exec --assume aws:default    -- aws s3 ls
```

For a plain env-var consumer — a server that just reads `GITHUB_TOKEN` — store
the token under the generic `env:` provider and exec materializes it at launch.
That is a deliberate raw-value delivery on your *own* config path, for a tool
that can't speak a broker:

```jsonc
// akasha put env:github GITHUB_TOKEN   (prompts, no echo)
"github": { "command": "akasha",
            "args": ["exec", "--assume", "env:github", "--", "github-mcp-server"] }
```

Either way the token lives in the vault, not your MCP config, and every assume
is audited. This is where Akasha sits in a multi-server world: not a proxy
across MCP, but the credential + audit layer **beneath** it that the other
servers draw from.

---

## Plugins — integrate any login as data

Akasha ships **no hard-coded providers**. AWS, GitHub, and a custom internal key
are the same kind of thing: a data-only YAML plugin. Drop one in
`~/.akasha/templates/` and the daemon can discover it, broker it from a secrets
manager, deliver it, and route an agent's tooling through it — **no Akasha
change, no PR**. (The shipped aws/github/… are exactly these files, just
curated.)

```yaml
# ~/.akasha/templates/datadog.yaml — brokered live from 1Password, never stored
kind: provider
name: datadog
version: 1
credential: {fields: {api_key: {secret: true}}}
source:
  - backend: onepassword-cli
    mode: on-demand
    ref: "op://Engineering/datadog/{instance}/credential"
    map: {value: api_key}
deliver:
  - mode: env
    env: {DD_API_KEY: "{api_key}"}
```

```bash
akasha template validate datadog.yaml   # parse + schema-check
akasha template explain  datadog         # capability manifest + dry run (no secret read)
akasha template trust    datadog         # approve before it can run a backend
```

**Safe by construction.** You select named *mechanisms* and supply
*parameters* — never a command. The daemon owns every binary, parser, and
renderer; the command in any ownership config is always the akasha binary. An
unsigned/unapproved plugin is **inert** until you `akasha template trust` it or
trust its publisher (Ed25519 signatures — `akasha publisher add`). So a
third party can publish a signed plugin and a user trusts the *author* once.

→ [Write a Plugin](docs/writing-a-plugin.md) · [Format reference](docs/PLUGIN_FORMAT.md)

---

## Use it from any agent (two lines)

```python
from akasha import Akasha

vault = Akasha(agent_id="support-bot-v2", api_key="agt_...")  # key from `akasha setup`

# Scan content before it reaches a tool or the LLM:
result = vault.wrap("send_email", "card 4111111111111111", task="Refund #8821")
# result.clean_content → "card vault://e4f5g6h7"

# Retrieve a secret safely — zeroed after the block, tool name enforced:
with vault.use(result.token, tool="stripe_charge", task="Refund #8821") as secret:
    stripe.charge(secret.value)
```

**LLM wrappers** (Ollama, LM Studio, OpenAI, Anthropic) scan messages, resolve
vault tokens in tool-call args, and vault tool results automatically:

```python
from akasha.integrations.openai_compat import AkashaOpenAI
client = AkashaOpenAI(agent_id="bot", api_key="agt_...",
                      base_url="http://localhost:11434/v1", llm_api_key="ollama")
```

---

## CLI

```bash
akasha setup                        # one-command install (see above)
akasha start                        # start the daemon manually
akasha status                       # health check + vault stats
akasha logs                         # tail the audit log (JSON lines)
akasha discover aws                 # scan + vault AWS credentials
akasha list                         # what can be assumed (provider:profile)
akasha assume aws:default           # eval $(...) to load creds into a shell
akasha inspect vault://abc12345     # token metadata (no decryption)
akasha vault backup [path]          # encrypted key backup (passphrase-protected)
akasha vault restore <file>         # recover a vault key from backup
akasha agent create <id>            # mint an agent API key
```

### Store a secret discovery didn't find

For anything `discover` doesn't pick up — a Stripe key, a database URL, any
custom token — `put` it under a label, then `assume` it like anything else. The
generic `env:` provider turns field names into environment variable names, so it
works for credentials with no native format:

```bash
akasha put env:stripe STRIPE_API_KEY          # prompts (no echo) for the value
akasha exec --assume env:stripe -- ./charge.sh # STRIPE_API_KEY is in the env

# agents / CI can pipe JSON instead of prompting:
echo '{"DATABASE_URL":"postgres://..."}' | akasha put env:db --stdin
```

Agents can do the same over MCP with the `vault_put` tool.

### Protect — make the vault the *only* copy

`discover` vaults a **copy**; the plaintext original stays on disk, readable
by any process. `protect` completes the move:

```bash
akasha protect ~/.aws/credentials
# ✓ escrowed (vault://…) — comment-only stub left on disk
```

The file's exact bytes and permissions now exist only in the vault; every
access is authenticated, audited, and policy-gated. Fully reversible:

```bash
akasha restore ~/.aws/credentials   # byte-for-byte, original mode
akasha restore --all
```

`akasha uninstall` restores every escrowed file automatically (on the purge
path too, before the vault is destroyed) — removing Akasha never breaks your
machine. Recommended before protecting anything: `akasha vault backup`.

### Custom detection patterns

Drop a `~/.akasha/patterns.yaml` to add org-specific patterns:

```yaml
- name: Acme Employee ID
  category: EmployeeID
  risk: high
  pattern: EMP-\d{6}
```

### Policy — gate what agents can access

Every path that hands a secret to an agent (`retrieve`, `assume`, the
credential helper, `grant`) is evaluated against `~/.akasha/policy.yaml`
first. First-match rules over agent, provider, category, risk, and tool
decide **allow**, **deny**, or **ask** — a native approval dialog that fails
closed (no answer = deny). No policy file = everything allowed; a broken one
denies all, loudly. Edits apply instantly, no restart.

```yaml
rules:
  - action: retrieve
    min_risk: critical
    effect: ask
    reason: critical data requires human approval
  - action: assume
    agent: experiment-bot
    provider: aws
    effect: deny
```

```bash
akasha policy init      # commented starter file
akasha policy validate  # after editing
```

Full reference: [docs/POLICY.md](docs/POLICY.md).

### Example audit log entry

```json
{
  "token": "vault://abc12345",
  "action": "VAULTED",
  "category": "CreditCard",
  "risk": "critical",
  "agent_id": "support-bot-v2",
  "tool_name": "send_email",
  "task": "Process refund for order #8821",
  "reasoning_trace": "User requested refund. Order verified. Initiating.",
  "triggered_by": "user message: 'I want my money back'",
  "timestamp": "2026-06-04T14:02:11Z"
}
```

---

## A2A Cross-Agent Grants

Akasha integrates naturally with the [A2A protocol](https://github.com/google-a2a/A2A). When Agent A delegates a task to Agent B via A2A, sensitive values in the task payload are replaced with vault tokens + grant IDs. The real value never travels over A2A.

```python
# Agent A — before sending an A2A task:
result = vault_a.wrap("lookup_account", f"SSN: {user_ssn}")

grant_id = vault_a.grant(
    token=result.token,
    grantee_agent="payment-bot-v1",
    allowed_tool="charge_card",
    task="Process refund for order #8821",
    ttl_seconds=300,
)

# A2A task payload — only tokens travel over the wire:
a2a_payload = {
    "task": "send_verification_email",
    "recipient_token": result.token,
    "akasha_grant": grant_id,
}

# Agent B — on receiving the A2A task:
real_value = vault_b.retrieve(
    grant_id=a2a_payload["akasha_grant"],
    requesting_tool="charge_card",
)
# Grants are single-use and tool-restricted.
```

---

## What Gets Detected

| Pattern | Category | Risk |
|---------|----------|------|
| `429-21-0001` | SSN | critical |
| `4111111111111111` | CreditCard | critical |
| `AKIA...` | APIKey (AWS) | critical |
| `api_key: sk-...` | APIKey | high |
| `password: ...` | Password | high |
| `user@example.com` | Email | medium |
| `(555) 867-5309` | Phone | medium |
| Tool name watchlist (`send_email`, `charge_card`, ...) | RiskyTool | varies |

Custom patterns are added via `~/.akasha/patterns.yaml` (see above). SSH keys and
Git tokens are also discovered and vaulted by `akasha setup`.

---

## Architecture

```
Agent (Claude Code / MCP, Python, Node, custom)
    ↓
akasha-py / MCP / CLI   ← thin clients
    ↓ unix socket / http
akasha daemon (Go)      ← single binary, no runtime deps
  ├── vault            SQLite + XChaCha20 + ML-KEM-768 (key in OS keychain)
  ├── template engine  data-only provider plugins (loaded from disk)
  ├── trust            signature (Ed25519) + hash-bound approval gate
  └── resolve          brokers from external secrets managers
    ↓
~/.akasha/             vault.db · templates.dist/ (shipped plugins) · templates/ (yours)
```

The vault and plugin engines live entirely in the Go daemon; clients are dumb
pipes. There are **no compiled-in providers** — the curated bundle ships as data
and is loaded through the same path as your own plugins.

---

## Repo Structure

```
akasha/
├── daemon/                   # Go core engine
│   ├── cmd/akasha/           # CLI (setup, template, publisher, assume, helper, …)
│   ├── templates/            # the shipped provider bundle (data, not compiled in)
│   └── internal/
│       ├── vault/            # XChaCha20 + ML-KEM + grants
│       ├── template/         # plugin format: parse / validate / discover
│       ├── trust/            # hash-bound approval store
│       ├── sign/ publisher/  # Ed25519 signing + trusted-publisher roots
│       ├── resolve/          # source backends (broker from secrets managers)
│       ├── assume/ setup/    # credential delivery + first-run wiring
│       ├── classifier/       # regex sensitivity detection
│       ├── server/ audit/    # unix socket + HTTP server, audit log
│       └── discover/         # native credential scanners (aws/ssh/git)
├── docs/                     # PLUGIN_FORMAT, THREATMODEL, getting-started, …
└── sdk/python/               # akasha-py thin client
```

---

## Roadmap

| Phase | Status |
|-------|--------|
| Go daemon (classifier, vault, server, CLI) | ✅ Done |
| Post-quantum crypto (XChaCha20 + ML-KEM-768) | ✅ Done |
| A2A grant system + reasoning provenance | ✅ Done |
| Python SDK + Anthropic/OpenAI integrations | ✅ Done |
| MCP server (Claude Code / Codex / Cursor) | ✅ Done |
| `vault_assume` credential handoff | ✅ Done |
| Credential discovery (AWS, SSH, Git) + key backup | ✅ Done |
| `akasha setup` one-command install | ✅ Done |
| Plugin format — no compiled-in providers, data-only YAML | ✅ Done |
| Authoring loop (`template validate/explain/trust`) | ✅ Done |
| Trust gate + Ed25519 signing + publisher marketplace | ✅ Done |
| Source resolvers — broker from a secrets manager (1Password) | ✅ Done (alpha) |
| Structured ownership mechanisms (no command injection) | ✅ Done |
| Local policy engine (`~/.akasha/policy.yaml`, allow/deny/ask at retrieve/assume) | ✅ Done |
| Per-operation human approval (fail-closed "ask", macOS dialog) | ✅ Done |
| `akasha protect` / `restore` — reversible escrow of plaintext credential files | ✅ Done |
| More source backends (Vault, AWS/GCP/Azure SM, http) | Planned |
| Resolver sandboxing · `mint` (least-privilege) execution | Planned |
| Harness-hook interception (payload classification, advisory) | Planned |
| `akasha run` — sandboxed agent launch (vault reachable only via daemon) | Later |
| Node.js SDK · Cloud audit dashboard · Consumer menubar app | Later |
| Enterprise SSO + compliance export + central policy management | Later |

---

## Privacy

- Encryption key lives in your OS keychain. Never on disk.
- Nothing leaves the machine without explicit opt-in.
- Cloud audit layer (Phase 3) receives only tokens and metadata — never the real sensitive values.
- Local LLM escalation (Ollama) is opt-in. Off by default.

---

## License

The Akasha daemon and SDKs are licensed under **Apache 2.0** (see [LICENSE](LICENSE)).
The hosted cloud control plane (team policy management, fleet enforcement,
dashboard) is a separate commercial product.
