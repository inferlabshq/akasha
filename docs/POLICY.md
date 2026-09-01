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
ask_requires: click       # click | passphrase — how strong an `ask` must be

rules:                    # first match wins
  - action: retrieve      # see the action table below (empty = any)
    agent: "vscode*"      # glob, case-insensitive (empty = any)  ADVISORY
    tool: send_email      # requesting tool                       ADVISORY
    provider: aws         # template name
    instance: prod        # profile/instance
    category: SSN         # vault entry classification
    min_risk: high        # matches high AND critical
    sandbox: true         # only a supervised `akasha run` (omit = either)
    caller: agent         # human (the local CLI) or agent (omit = either)
    brokerable: true      # provider has a per-operation route (omit = either)
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

### Making an `ask` something an agent cannot answer

`effect: ask` shows a dialog. That already stops a background process vending
*silently* — a window appears — but a dialog is UI, and a process running as you
can drive UI automation. So a button converts silent theft into noisy theft
rather than preventing it.

`ask_requires: passphrase` asks for a secret instead:

```yaml
ask_requires: passphrase
rules:
  - {action: broker, provider: aws, instance: prod, effect: ask}
```

Set it once, from a terminal:

```
akasha policy passphrase
```

Why this works where identity does not: you **cannot** establish the identity of
another process running as your own user — see
[the design note](design/same-user-identity.md), which states that as a theorem.
This does not try. It makes the *authority* something a background process
cannot produce. A process that can read every file you own still cannot produce
a passphrase you only ever typed.

It is **not** a second encryption key and **not** your vault passphrase. It
decrypts nothing; if it leaked, the holder could answer a prompt and nothing
else. It is stored only as an Argon2id verifier and cannot be read back.

**It fails closed.** If no passphrase is configured, or the machine's dialog
cannot ask for one, an `ask` rule requiring it **denies** — it never falls back
to a button. A factor that cannot be checked has not been satisfied.

`ask_requires: touch-id` is refused at parse rather than accepted. It needs
LocalAuthentication, the released binaries are built without cgo, and a policy
that reports a protection it is not applying is worse than one that says no.

Use it for the credentials worth the friction, not the routine broker path.

### A matcher this daemon does not know

A rule may name a matcher a newer Akasha understands and this one does not. The
file is **not** rejected — rejecting it would make every gated operation fail,
which is a worse outcome than the rule itself could ever cause. Instead the
unrecognized condition is treated as one the daemon cannot claim to have
applied, using the same asymmetry as an unrankable risk:

| Rule effect | With a matcher this daemon cannot evaluate |
|---|---|
| `deny` / `ask` | **still matches** — the unevaluated condition could only have narrowed it, so ignoring it is the restrictive read |
| `allow` | **never matches** — an allow is not granted on a condition that was never checked |

So downgrading a daemon makes a policy *more* restrictive, never less. Only
rules carrying an unknown key are affected; the rest of the file behaves exactly
as written.

Two things stay fatal, and both deny every operation until fixed: a malformed
document, and an unknown key at the **top level** — a document key defines what
the file means, and that is not something to guess at.

`akasha policy validate` stays strict and reports an unknown matcher as an
error, so a typo is caught while you are writing the file rather than silently
weakening a rule.

### Which matchers you can trust

`action`, `provider`, `instance`, `category`, `min_risk`, `sandbox` and
`caller` are established by the daemon from the endpoint that ran, the key that
authenticated, and the vault entry itself. A caller cannot choose them.

`sandbox:` and `caller:` are the two that describe the *situation* rather than
the secret, and they are the ones that express a lifetime policy:

```yaml
rules:
  # An agent never takes a session credential for a provider that has a
  # per-operation route. `brokerable` is read from the provider's own template,
  # so this names no providers: it covers aws/github/git/gitlab, and leaves ssh
  # and gcp alone because they have no alternative route.
  - {action: assume, caller: agent, brokerable: true, effect: deny,
     reason: use the per-operation route}
  # Using one an operation at a time is routine.
  - {action: broker, effect: allow}
  # A person at a terminal is not who that rule is about.
  - {action: assume, caller: human, effect: allow}
```

The daemon has **no opinion of its own** about session-versus-per-operation.
The template declares the route it has, this rule decides what follows, and the
daemon only evaluates. With no such rule installed nothing is routed.

That is the whole of "reuse vs per-operation": **`assume` is the reuse mode and
`broker` is the per-operation mode**, and they have always been separate verbs.
There is no `lifetime:` key, because there is nothing for one to say that these
two do not already say.

Two things this does **not** buy, stated plainly because the opposite is easy to
assume:

- **Per-operation does not contain a compromise.** Akasha hands back a stored
  credential; it does not mint a new one. The bytes are identical across
  issuances, so an attacker who observes one operation holds a working
  credential until you rotate it at the provider. What per-operation buys is
  **attribution** (every use is a separate audit record) and **disk residency**
  (nothing is written to disk at all).
- **Expiry is not revocation.** A TTL removes the materialized *file*. The
  credential stays valid upstream, and a process that already read it is
  unaffected.

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
> this page used to document **never fired** — it read as "approve every escrow
> read" and silently matched nothing. If you relied on `[abc]` character classes (an
> undocumented side effect of `filepath.Match`), they are now literal text.

Credential reads (`/credential/retrieve`, which resolves a name and returns the
decrypted value) are gated as `assume`, with the label's prefix as the provider.

### Escrow is not gated by policy — it is gated by identity

> **Changed in 0.1.0-alpha.4.** This section previously recommended
> `{action: assume, provider: escrow, instance: "*", effect: ask}` as the way to
> protect escrowed files. Do not write that rule. It was never shipped, so under
> the default policy a key-holding agent read a whole escrowed credentials file
> in one request — and writing it does not fix that so much as move the damage:
> `ask` fails closed on a headless machine, and `deny` refuses outright, so the
> rule locks **you** out of your own file while `akasha restore` is the only way
> to get it back.

An `escrow:` entry is the verbatim content of a file you took off disk, so
unlike every other credential it has no brokered form — reading the entry *is*
reading the plaintext. The daemon therefore refuses `escrow:` to any caller that
is not the local CLI, in code rather than by a rule: an agent cannot read, list,
bind or unbind one, whatever the policy file says. You keep full access, and
`akasha uninstall` restores escrowed files without crossing the boundary at all.

The two gates run in that order: **policy first, then the identity gate**. So a
rule that denies you is still honoured — if you write one, `akasha uninstall` is
the escape hatch that puts every escrowed file back on disk — and no rule that
allows an agent can open the gate, because the gate is not asking policy.

Being the human is not a licence to lose the file, either. An escrow label is
the only handle on the original, so the daemon refuses to remove **or
re-point** one — `akasha put escrow:<path>` included — while the file it names
is not back on disk. `akasha restore <path>` clears the refusal;
`akasha label rm --destroy-escrowed-original <label>` is the one command that
overrides it, and it is named after what it does.

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
  - **Linux**: a `zenity` dialog with the same buttons and the same default
    Deny. The systemd user unit reaches your desktop through the environment
    the session imports — the same import that gives the daemon the D-Bus
    session bus its keyring needs. If `DISPLAY`/`WAYLAND_DISPLAY` never made it
    into the unit, run:

    ```
    systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY
    systemctl --user restart akasha
    ```

    Only `zenity` is used. `kdialog` is deliberately not a fallback: it has no
    default-no button, and it returns the same exit code for "No" and for
    "dismissed with Escape", so there is no way to wire it that does not either
    default to Allow or treat an Escape as one. KDE users can install `zenity`
    alongside their desktop.
  - **Headless, or no dialog program**: `ask` behaves as `deny`, and the error
    says which of the two it was — "no graphical session…" or "zenity is not
    installed…" — rather than reporting a refusal nobody made.

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
> `akasha list` from your own shell arrives as `akasha-list`, `restore` as
> `akasha-assume` and `put` as `akasha-bind`, none of which match `claude`.
> (Those daemon-assigned names identify the local human; an agent's own verified
> identity replaces them, so a rule written against `claude` still matches when
> Claude is the caller.) The example above
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
