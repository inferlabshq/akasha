# Local retrieval policy

Akasha's policy engine evaluates every operation that would hand secret
material to an agent — `/retrieve`, `/assume`, the credential helper
(`credential_process` / git credential calls), and `/grant` — against
`~/.akasha/policy.yaml` **before** the vault is touched. This is the choke
point: for anything vaulted or brokered, there is no path to the secret that
skips it.

```
agent → MCP / SDK / helper → daemon socket → policy → vault/broker → secret
                                        └── deny / ask ──► DENIED (audited)
```

## Quick start

```bash
akasha policy init       # write a commented starter policy
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
  - action: retrieve      # retrieve | assume | grant (empty = any)
    agent: "vscode*"      # glob, case-insensitive (empty = any)
    tool: send_email      # requesting tool
    provider: aws         # assume-path: template name
    instance: prod        # assume-path: profile/instance
    category: SSN         # vault entry classification
    min_risk: high        # matches high AND critical
    effect: ask           # allow | deny | ask
    reason: shown to the agent and written to the audit log
```

All matcher fields are optional; an empty field matches anything. `min_risk`
is a threshold (`high` matches `high` and `critical`). The `assume` path is
always evaluated as `category: Credential`, `min_risk: critical` — handing an
agent a working credential is critical by definition, regardless of how the
underlying fields were classified. Label lookups (`/label/get`) are gated the
same way, with the label's prefix as the provider — so files escrowed with
`akasha protect` can be gated with `provider: escrow` (e.g. `effect: ask` to
require approval before anything reads an escrowed original back out).

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
  - action: assume
    agent: claude
    provider: aws
    instance: dev
    effect: allow
  - action: retrieve
    agent: claude
    min_risk: medium     # medium and above still needs a human
    effect: ask
  - action: retrieve
    agent: claude
    effect: allow        # low-risk: fine
```

## What policy can and cannot promise

Policy is enforced at the daemon socket, which is the only path to anything
**vaulted or brokered** — that enforcement cannot be bypassed by an agent,
because the plaintext doesn't exist anywhere else it can reach. For
credentials that still sit in plaintext files on disk (anything `discover`
found but you haven't escrowed), policy governs the *Akasha* path, not the
raw file. See the enforcement ladder in
[THREATMODEL.md](THREATMODEL.md#enforcement-ladder-honest-positioning).
