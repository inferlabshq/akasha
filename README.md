# Akasha

**A local vault for AI agents.** Akasha automatically detects and captures sensitive data from agent tool calls before it can leak — replacing real values with `vault://` tokens — and maintains a full audit trail of everything agents touched.

Named after the Hindu concept of the cosmic ether that records every event in the universe.

**Core trust guarantee: sensitive data never leaves the machine.**

> **Status: alpha.** Pre-1.0 — don't use it to protect secrets you can't rotate.
> Read the [Threat Model](docs/THREATMODEL.md) and [Security Policy](SECURITY.md).

**Docs** → [Getting Started](docs/getting-started.md) · [Why trust this?](#why-would-i-trust-this) · [FAQ](#faq) · [Write a Plugin](docs/writing-a-plugin.md) · [Policy](docs/POLICY.md) · [all documentation →](docs/)

---

## Quick Start

```bash
curl -sSL https://getakasha.dev/install | sh
akasha setup
```

**From a checkout** (contributors) — the installer detects it and builds your
working tree rather than downloading the published binary:

```bash
sh install.sh
akasha setup
```

On macOS the first install asks once whether `codesign` may use a local signing
key; click **Always Allow**. That key is what keeps your vault's keychain access
stable across updates — decline it and akasha still works, but every update
re-prompts for keychain access.

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
# lifecycle
akasha setup                        # first-run setup — configure agents and start the daemon
akasha start                        # start the Akasha daemon
akasha status                       # health check and vault statistics
akasha version                      # print the akasha version + trust-root status
akasha uninstall [--purge]          # stop & deregister the daemon; optionally purge the vault

# credentials
akasha discover all                 # discover credentials on this machine and vault them
akasha list [provider]              # list assumable credentials (provider:profile)
akasha put env:stripe STRIPE_API_KEY  # store a secret under a label so `assume` can use it
akasha label rm ssh:old-key         # remove a credential's name (the secret itself is kept)
akasha assume aws:default           # assume a vaulted credential into the current shell
akasha whoami aws:default           # which account/principal a credential belongs to
akasha inspect vault://abc12345     # metadata for a vault token (no decryption)
akasha protect ~/.aws/credentials   # move a plaintext credential file INTO the vault
akasha restore [--all] <file>       # write an escrowed original back, byte-for-byte

# running things
akasha exec --assume aws:default -- aws s3 ls    # run a command with vaulted credentials
akasha run claude --assume github:work -- claude # launch an agent in an OS sandbox
akasha helper aws --instance default             # resolve on demand (credential_process hook)

# governance
akasha policy                       # show the local retrieval policy (~/.akasha/policy.yaml)
akasha policy init                  # write a commented starter policy.yaml
akasha policy validate              # check it parses (a broken file denies everything)
akasha logs                         # tail the local audit log (JSON lines)
akasha agent create <id>            # mint an agent API key
akasha agent list / revoke <key-id> # see and revoke agent keys
akasha vault backup [path]          # encrypted key backup (passphrase-protected)
akasha vault restore <file>         # recover a vault key from backup

# plugins
akasha template list                # loaded plugins (built-in and user) with capabilities
akasha template validate <file>     # parse and schema-check a plugin file
akasha template explain <name>      # what it can do + a dry run (no secret read)
akasha template trust <name>        # approve its high-trust effects (hash-bound)
akasha publisher add <id> <key>     # trust a signing publisher
```

`akasha run` takes `--assume provider:instance` (repeatable) for what the run
may broker, plus `--ttl`, `--allow-read` / `--allow-write` for extra sandbox
paths, `--print-profile` to see the profile without launching, and
`--no-sandbox` to launch without isolation. `akasha --help` lists every command;
`akasha <command> --help` its real flags.

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
  "token": "tk_9f2c4a7e1b03",
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

`token` is a stable digest, not the vault token. It correlates every event about
the same secret — which is all the audit trail ever needed it for — without the
log becoming a list of live credentials to try.

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
│   ├── cmd/akasha/           # CLI (setup, template, publisher, assume, helper, run, …)
│   ├── templates/            # the shipped provider bundle (data, not compiled in)
│   └── internal/
│       ├── vault/ crypto/    # XChaCha20 + ML-KEM + grants
│       ├── template/         # plugin format: parse / validate / discover
│       ├── trust/            # hash-bound approval store
│       ├── sign/ publisher/  # Ed25519 signing + trusted-publisher roots
│       ├── resolve/          # source backends (broker from secrets managers)
│       ├── assume/ setup/    # credential delivery + first-run wiring
│       ├── provision/        # discovered credential → vaulted, labelled entry
│       ├── escrow/           # `protect` / `restore` — reversible file escrow
│       ├── identity/         # non-secret facts about a credential (`whoami`)
│       ├── classifier/       # regex sensitivity detection
│       ├── policy/           # local allow/deny/ask rules at the choke point
│       ├── sandbox/          # OS sandbox for `akasha run` (macOS + Linux)
│       ├── mcp/              # MCP server over stdio (a proxy to the daemon)
│       ├── clikey/           # the local CLI's own agent identity
│       └── server/ audit/    # unix socket + HTTP server, audit log
├── docs/                     # indexed in docs/README.md (plugins, policy, threat model, …)
└── sdk/python/               # akasha-py thin client
```

There is no `internal/discover/`: the native aws/ssh/git scanners were removed
in favour of the declarative `discover:` rules in the provider bundle, so
discovery has one implementation (`internal/template`) for shipped and
user-written plugins alike.

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
| `akasha run` — OS-sandboxed agent launch, per-run identity, broker-only credentials | ✅ alpha (macOS + Linux) |
| Node.js SDK · Cloud audit dashboard · Consumer menubar app | Later |
| Enterprise SSO + compliance export + central policy management | Later |

---

## Why would I trust this?

You shouldn't, on assertion. Here is what is checkable.

**An agent runs as your user.** That is the fact everything else has to be honest
about. Any mechanism installed by writing config — MCP entries, environment
variables, harness hooks — can in principle be un-configured by a process with
the same privileges. Akasha does not claim otherwise, and the
[Threat Model](docs/THREATMODEL.md) states what each tier does and does not buy,
and keeps a running list of known limitations we would rather you read than
discover.

**The strongest guarantee is possession, not interception.** A secret that exists
*only* in the vault — agent-stored values, and any file you escrow with
`akasha protect` — has no plaintext left to steal. Bypassing the interception
layers gains nothing, because there is nothing on disk to read. `discover` alone
vaults *copies*; the originals stay where they are until you escrow them, and
`akasha restore` (and uninstall, automatically) puts them back byte-for-byte.

**Providers are data, not code.** A plugin selects from a closed set of Go
primitives and supplies charset-validated parameters. There is no `command`
field anywhere in the format, no shell, no expression language, and deliberately
no arbitrary-`exec` backend — so there is no slot to inject one. The registry is
frozen: new capability means a new named entry in Go, never a new top-level key.
The shipped bundle is Ed25519-signed against a trust root compiled into the
binary; a template you write yourself stays inert until you approve it, and the
approval is bound to that file's hash, so editing it revokes trust.

**Nothing phones home.** Every non-test source file was grepped for outbound
URLs; the only hits are a Unix-socket authority and test fixtures. The audit log
is local. There is no telemetry to disable.

**Every caller authenticates, including you.** A request without a key is
refused outright. That reversed an earlier design where a keyless call was read
as the trusted human — which meant a revoked agent could regain *more* access by
presenting *less*. Privilege is now monotonic in authentication.

**It is Apache 2.0 and the interesting parts are small.** The trust boundary is
one file (`daemon/internal/server/server.go`), the policy engine another, and
the plugin format is a few hundred lines of enum validation. You can read the
parts that matter in an afternoon, which is the point.

---

## FAQ

**What actually stops an agent from just reading `~/.aws/credentials`?**
For a discovered credential: nothing, until you run `akasha protect` — discovery
vaults a copy and the original stays put. Once escrowed, the file is gone and the
only path is the daemon, which authenticates, gates and audits every request.
Before that, what you get is *ownership of the default path*: the agent's session
is pointed at a broker, and the real file is replaced with an empty decoy. That
governs well-behaved and casually-misbehaving agents. It is drift protection, not
a cage, and we label it that way in the ladder.

**Isn't this security theatre if the agent shares my UID?**
It would be, if we claimed containment we don't have. We don't. Three tiers,
descending in strength: possession (real), environment ownership (drift
protection), and supervised launch via `akasha run` (an OS sandbox plus a
broker-only capability profile bound to the run's verified identity, enforced on
every listener). None of them survive an attacker who already owns your account,
and the threat model says so in those words.

**What happens when it breaks?**
It fails closed and loudly. An unparseable policy denies everything; a deleted
policy is detected by a digest tripwire and denied, not silently reverted to
allow-all; an approval prompt with no approver denies; a credential whose risk or
category cannot be read still matches deny rules rather than slipping past them.
The sandbox proves itself on every launch and refuses to start if the profile
isn't actually enforcing.

**Can I get my secrets back out?**
Yes, and the uninstall path is part of the product rather than an afterthought.
`akasha uninstall` restores every escrowed file byte-for-byte before it removes
anything, and `--export` writes a passphrase-encrypted bundle you can restore
elsewhere. Discovered credentials were only ever copies. The one thing that is
genuinely destroyed by `--purge` is an agent-stored secret with no other source —
so it warns you, counts them, and tells you to export first.

**`curl | sh` — really?**
It is a fair objection. The script is POSIX `sh`, it verifies a SHA-256 checksum
before installing anything, it refuses on mismatch, and it will build from source
instead if you prefer (`AKASHA_BUILD_FROM_SOURCE=1`). Read it first — that is the
correct instinct and the script is written to be read. On a checkout it builds
your working tree rather than downloading, so contributors never get a surprise
binary.

**Do you see any of my data?**
No. There is no server. Alpha binaries are unsigned by Apple; the installer
code-signs locally with a stable per-machine certificate so that replacing the
binary doesn't churn your keychain ACL.

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
