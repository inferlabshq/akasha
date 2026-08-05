# Local retrieval policy

Akasha's policy engine evaluates every operation that would hand secret
material to an agent — `/retrieve`, `/assume`, the credential helper
(`credential_process` / git credential calls), and `/grant` — against
`~/.akasha/policy.yaml` **before** the vault is touched.

The engine gates every read path through the daemon. It does **not** gate the
human's own direct access to the vault file (`akasha vault`, `akasha agent`, and
anything else that opens `vault.db` without going through the socket), and it
cannot defend against a process that already has your UID and can simply edit or
delete `policy.yaml`. The policy engine raises the cost of accidental and
prompt-injected misuse; it is not a containment boundary against an attacker who
already holds your user account. See the
[Threat Model](THREATMODEL.md#enforcement-ladder-honest-positioning).

```
agent → MCP / SDK / helper → daemon socket → policy → vault/broker → secret
                                        └── deny / ask ──► DENIED (audited)
```

## Use, don't read — the model Akasha ships

Two verbs, and the policy keeps them apart:

- **USE (brokered).** The git/AWS credential helper resolves a secret *per
  operation* and hands it straight to the tool — it never enters the agent's
  context. This is `action: broker`, and it is **allowed**: it is how an agent is
  meant to use a credential.
- **READ (raw).** Returning plaintext into a caller's context — an agent's
  `vault_retrieve`. This is **denied**: an agent uses a credential through the
  broker; it never reads the value.

`akasha policy init` (and the daemon's default when there is no file) ship
exactly this, plus a light touch on delegation:

```yaml
rules:
  - {action: retrieve, effect: deny}              # READ → raw value
  - {action: grant, min_risk: high, effect: ask}  # risky delegation → human
  - {action: grant, effect: allow}                # routine delegation
# broker and assume fall through to `default: allow`
```

> **Changed in 0.1.0-alpha.3.** USE used to be expressed as `action: retrieve` +
> `tool: akasha_helper` → allow. That was a **bypass**: `tool` comes from the
> request body, so any caller that wrote the string `akasha_helper` satisfied the
> allow rule and read raw plaintext — including a prompt-injected agent, since
> `requesting_tool` is an ordinary argument of the `vault_retrieve` MCP tool.
> Brokered use now has its own server-assigned action (`broker`), the `akasha_*`
> tool namespace is refused in request bodies, and the exception rule is gone.
> **If your `policy.yaml` still contains that rule, delete it** — `akasha policy
> validate` will point it out.

`assume` is intentionally left to `default: allow` so routine git/AWS use does
not interrupt you. Materializing a raw secret into a **verified agent's**
environment is already refused by the daemon — no policy rule can loosen that —
and brokered providers resolve per operation through the helper. Add an `assume`
rule only to gate a specific case, and gate it by `provider`/`agent`: assume is
always evaluated as `critical` (see [Format](#format)), so `min_risk` cannot
distinguish a routine assume from a risky one.

## Quick start

```bash
akasha policy init       # write the seamless-broker starter policy above
akasha policy            # show the current policy + validity
akasha policy validate   # after editing
```

No policy file means **everything is allowed** — the engine is opt-in and
adds no friction until you ask for it. Edits take effect on the next
operation; the daemon never needs a restart.

## Format

```yaml
version: 1
default: allow            # or deny (lockdown: only rule-matched ops pass)
ask_timeout_seconds: 60   # how long an approval dialog waits (then denies)

rules:                    # first match wins
  - action: retrieve      # see the action table below (empty = any)
    agent: "vscode*"      # glob, case-insensitive (empty = any)  ADVISORY
    tool: send_email      # requesting tool                       ADVISORY
    provider: aws         # template name
    instance: prod        # profile/instance
    category: SSN         # vault entry classification
    min_risk: high        # matches high AND critical
    effect: ask           # allow | deny | ask
    reason: shown to the agent and written to the audit log
```

### Actions

| Action | Operation | Hands out a secret? |
|---|---|---|
| `retrieve` | raw value into the caller's context (`vault_retrieve`) | yes, raw |
| `broker` | resolve for ONE operation (credential helper) | yes, per-op |
| `assume` | materialize for a whole session | yes, session |
| `grant` | delegate a token to another agent | indirectly |
| `inspect` / `list` | metadata and inventory | no |
| `bind` | point a label at a secret (`/label/set`, `/put`, `/profile/save`) | no — but redirects what later ops resolve to |
| `purge` | garbage-collect orphaned discovery entries | no — destructive |

`bind` is tagged `high` for a new label and **`critical` when re-pointing an
existing one**, so `min_risk: critical` singles out the case that matters: an
agent that can re-point `aws:default` redirects your own tooling at a credential
it controls.

### Which matchers you can trust

`action`, `provider`, `instance`, `category` and `min_risk` are established by
the daemon from the endpoint that ran and the vault entry itself. A caller
cannot choose them.

`agent:` and `tool:` depend on **how the identity was established**, and the
daemon enforces the difference — an identity the caller asserted can narrow a
`deny` or `ask`, but **can never satisfy an `allow`**:

| How the identity arose | Example | Can satisfy an `allow`? |
|---|---|---|
| **Key-verified** — caller sent a valid `X-Akasha-Key` | `agent: claude` from a configured MCP client | **yes** |
| **Daemon-assigned** — the endpoint names its own caller and ignores the body | `agent: akasha-helper` on the broker path, `akasha-list`, `akasha-bind`, `akasha-assume`, `akasha-inspect`, `akasha-purge` | **yes** — the name cannot be claimed |
| **Caller-asserted** — read from the request body | `agent_id` / `requesting_tool` on `/retrieve`, `/grant`, `/wrap`, `/store` | **no** |

> **Changed in 0.1.0-alpha.3.** This was previously documented guidance that the
> engine did not enforce, which is how the shipped starter policy came to grant
> raw secret reads to anyone who wrote `requesting_tool: akasha_helper`. If a
> rule of yours stops granting, the caller is almost certainly missing its agent
> key — `akasha status` reports that, and `akasha policy validate` names the
> affected rules.

All matcher fields are optional; an empty field matches anything. `min_risk`
is a threshold (`high` matches `high` and `critical`). The `assume` path is
always evaluated as `category: Credential`, `min_risk: critical` — handing an
agent a working credential is critical by definition, regardless of how the
underlying fields were classified.

**Unclassified risk is treated as unknown, not as low**, and the two kinds of
rule handle it in opposite directions:

- a `deny` or `ask` rule with `min_risk` **matches** an entry whose risk cannot
  be ranked — "deny anything high or above" has to cover a secret you cannot
  rank, or it does not mean what it says;
- an `allow` rule with `min_risk` **does not** — granting on the strength of a
  level nobody could read would be the same mistake inverted.

> **Changed in 0.1.0-alpha.3.** An unrecognised risk used to rank below every
> threshold, so restrictive `min_risk` rules silently stopped applying. Combined
> with `risk` being a free-text field on an ungated endpoint, an agent could
> vault a secret as `criticall` — one typo from a real level — and put it beyond
> the reach of every rule. `/store` now rejects a risk it cannot rank, and so
> does the classifier's pattern config.

### Glob syntax

`*` matches any run of characters **including `/`**, `?` matches exactly one
character, and every other character — `[`, `]`, `\` included — is literal.
Matching is case-insensitive. There is no such thing as an invalid pattern, so
a rule can never be silently disabled by a typo in a matcher.

> **Changed in 0.1.0-alpha.3.** Matching previously used Go's `filepath.Match`,
> whose `*` stops at a `/` because it is designed for paths. Policy matchers
> hold identifiers, and escrow instances are absolute paths, so the escrow rule
> documented below **never fired** — it read as "approve every escrow read" and
> silently matched nothing. If you relied on `[abc]` character classes (an
> undocumented side effect of `filepath.Match`), they are now literal text.

Label lookups (`/label/get`) are gated as `assume`, with the label's prefix as
the provider — so files escrowed with `akasha protect` can be gated with
`provider: escrow`, e.g. require approval before anything reads an escrowed
original back out:

```yaml
  - {action: assume, provider: escrow, instance: "*", effect: ask}
```

A secret reachable under more than one label name is evaluated against **all**
of them, and denied if any is denied. Binding a second name to a secret
therefore cannot be used to walk past a rule written for the first.

## Effects

- **allow** — proceed (still audited as usual).
- **deny** — the operation fails with 403 and the rule's reason; a `DENIED`
  event is written to the audit log.
- **ask** — the operation pauses for interactive human approval and **fails
  closed**: no response within `ask_timeout_seconds` is a deny.
  - **macOS**: a native dialog (Deny / Allow, default Deny) via the login
    session. The daemon runs as a launchd user agent, so the dialog appears
    on your desktop.
  - **Linux / headless**: no interactive channel is implemented yet, so `ask`
    currently behaves as `deny` (with a reason saying approval was
    unavailable). A pending-approvals CLI is planned.

## Failure semantics (deliberate)

- **Missing file → allow all.** The engine is opt-in.
- **Unparseable file → deny all, loudly.** A security control that silently
  stops applying is worse than one that fails closed. `akasha policy
  validate` tells you exactly what's wrong; fixing the file restores service
  immediately.
- **Policy denial never burns a grant.** Grant-based retrievals are checked
  before redemption, so a denied single-use grant can be retried once policy
  permits.

## Examples

Pause for approval on anything critical, block one agent from production AWS:

```yaml
rules:
  - action: retrieve
    min_risk: critical
    effect: ask
    reason: critical data requires human approval
  - action: assume
    agent: experiment-bot
    provider: aws
    instance: prod
    effect: deny
    reason: experiment-bot stays out of prod
```

Lockdown posture — nothing moves unless explicitly allowed:

```yaml
default: deny
rules:
  # Your own commands. The daemon names these callers itself, so the names
  # cannot be claimed by an agent — see "Which matchers you can trust".
  - {action: broker, agent: akasha-helper, effect: allow}   # git/aws per operation
  - {action: list,   agent: akasha-list,   effect: allow}   # akasha list
  - {action: inspect, agent: akasha-inspect, effect: allow}
  - {action: bind,   agent: akasha-bind,   effect: allow}   # discover / setup / put
  - {action: purge,  agent: akasha-purge,  effect: allow}
  - {action: assume, agent: akasha-assume, effect: allow}   # akasha assume / exec / restore

  # A keyed agent. `agent: claude` only grants to a caller holding claude's
  # key, so this cannot be opened by an agent typing the name.
  - action: retrieve
    agent: claude
    min_risk: medium     # medium and above still needs a human
    effect: ask
  - action: retrieve
    agent: claude
    effect: allow        # low-risk: fine
```

> **Corrected in 0.1.0-alpha.3.** The previous version of this example listed
> only `agent: claude` rules. Under `default: deny` that denies your own CLI:
> a keyless `akasha list` arrives as `akasha-list`, `restore` as `akasha-assume`
> and `put` as `akasha-bind`, none of which match `claude`. The example above
> allows the daemon-assigned identities explicitly. Start from `default: allow`
> and tighten, rather than adopting a lockdown wholesale — and run each command
> you rely on once afterwards.

## What policy can and cannot promise

Policy is enforced at the daemon socket, which is the only path to anything
**vaulted or brokered** — that enforcement cannot be bypassed by an agent,
because the plaintext doesn't exist anywhere else it can reach. For
credentials that still sit in plaintext files on disk (anything `discover`
found but you haven't escrowed), policy governs the *Akasha* path, not the
raw file. See the enforcement ladder in
[THREATMODEL.md](THREATMODEL.md#enforcement-ladder-honest-positioning).
