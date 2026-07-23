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

## Where things live

| path | what |
|---|---|
| `~/.akasha/vault.db` | the encrypted vault (XChaCha20 + ML-KEM-768; key in the OS keychain) |
| `~/.akasha/templates.dist/` | the shipped provider bundle (data, not compiled in) |
| `~/.akasha/templates/` | **your** plugins — drop a YAML here to add a provider |
| `~/.akasha/agents/<id>/` | generated per-agent config (e.g. the `aws.config` that routes through the daemon) |
| `~/.akasha/audit.log` | what was accessed, by which agent, and why |

## Inspect

```bash
akasha status        # health + vault stats
akasha logs          # the audit trail
```

## Next

The point of Akasha is that **any** login is just data. See
[Writing a Plugin](writing-a-plugin.md) to integrate a new service with no
Akasha change and no PR.
