# Getting Started

Akasha is a local vault for AI agents: it holds your credentials, hands agents
short-lived access through audited channels, and keeps the real secrets off the
agent's hands. This is the 5-minute path from install to a working setup.

## 1. Install

```bash
curl -sSL https://getakasha.dev/install | sh
```

This installs the `akasha` binary to `~/.local/bin` and places the curated
provider bundle (aws, github, …) on disk. Add `~/.local/bin` to your `PATH` if
it isn't already.

> Building from source instead: `cd daemon && go build -o ~/.local/bin/akasha ./cmd/akasha`,
> then copy `daemon/templates/*.yaml` into `~/.akasha/templates.dist`.

## 2. Set up

```bash
akasha setup
```

This:
- starts the daemon as a login service,
- scans your machine for credentials (AWS profiles, SSH keys, git tokens) and
  vaults them,
- configures any installed agent IDEs (Claude Code, Cursor, VS Code) to route
  through Akasha.

Ownership of an agent's environment is a high-trust action, so providers that
want it start **untrusted**. Approve the ones you want after reviewing them:

```bash
akasha template list                 # see providers + trust status
akasha template explain aws          # see exactly what it would do
akasha template trust aws            # approve it (hash-bound)
```

## 3. Use it

**Assume a credential** (writes a short-lived, RAM-backed credential file):

```bash
akasha assume aws:default            # then use the aws CLI normally
akasha list                          # what's assumable
```

**Inside an agent session**, once a provider is trusted, your tooling resolves
through the daemon automatically — e.g. `aws` calls hit
`credential_process = akasha helper aws …`, so the agent gets a fresh,
audited credential per call and never holds the raw secret.

**Wrap any process** so it gets a credential injected just for its run:

```bash
akasha exec --assume aws:default -- aws s3 ls
```

**Check what a credential actually is** before you use it — which account, which
kind of key — without assuming it, using it, or making a network call. Only the
non-secret fields a named contract declares are read, and no contract can echo
back what it was given:

```bash
akasha whoami aws:default
```

**Launch an agent under supervision.** `exec` wires one command you chose;
`run` supervises a whole agent session inside an OS sandbox where the vault,
the OS keychain and your plaintext credential files are unreachable, under a
per-run identity that may broker only what you named:

```bash
akasha run claude --assume github:work -- claude
```

The run's credentials are revoked the moment the supervisor exits. It does not
confine the network, and a process inside can still read the plaintext of a
credential it is allowed to use — see the [threat model](THREATMODEL.md) for
exactly what tier 3 promises.

## 4. Make the vault the only copy

This is the step that turns "Akasha holds your credentials" from a description
into a guarantee. **`discover` vaults a *copy*** — the plaintext original is
still sitting in `~/.aws/credentials`, readable by any process on the machine.
`protect` completes the move:

```bash
akasha vault backup                 # do this first — protects against keychain loss
akasha protect ~/.aws/credentials
```

The file's exact bytes and permissions now exist only in the vault, and the
file on disk becomes a comment-only stub. Every access flows through the
daemon: authenticated, audited, policy-gated. Your agents keep working through
`credential_process`; for your own shell, use `akasha exec --assume`.

Fully reversible, byte-for-byte:

```bash
akasha restore ~/.aws/credentials
akasha restore --all
```

`akasha uninstall` restores every escrowed file automatically, so removing
Akasha never leaves your machine missing a credential.

## Tidying up

Discovery creates names; `label rm` removes one that has gone stale (a renamed
key, a retired profile, a typo). It removes the **name**, not the secret:

```bash
akasha label rm ssh:old-laptop
```

## Where things live

| path | what |
|---|---|
| `~/.akasha/vault.db` | the encrypted vault (XChaCha20 + ML-KEM-768; key in the OS keychain) |
| `~/.akasha/templates.dist/` | the shipped provider bundle (data, not compiled in) |
| `~/.akasha/templates/` | **your** plugins — drop a YAML here to add a provider |
| `~/.akasha/agents/<id>/` | generated per-agent config (e.g. the `aws.config` that routes through the daemon) |
| `~/.akasha/policy.yaml` | first-match allow/deny/ask rules, checked before any secret is handed out. No file = everything allowed; a broken one denies all, loudly. See [POLICY.md](POLICY.md) |
| `~/.akasha/approvals.json` | which plugins you trusted, each bound to that file's SHA-256 — editing a plugin revokes its approval |
| `~/.akasha/audit.log` | what was accessed, by which agent, and why |

## Inspect

```bash
akasha status        # health + vault stats
akasha logs          # the audit trail
akasha policy        # the rules every retrieval is evaluated against
```

## Next

The point of Akasha is that **any** login is just data. See
[Writing a Plugin](writing-a-plugin.md) to integrate a new service with no
Akasha change and no PR.
