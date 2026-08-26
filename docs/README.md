# Akasha Documentation

Akasha is a local vault that lets an AI agent **use** a credential without ever
**holding** the raw secret. Two pieces make that real, and each has a doc:

- **Plugins** describe how a login is brokered — as data, not code.
- **Policy** decides, per operation, what's allowed, denied, or held for a human.

## Start here

- **[Getting Started](getting-started.md)** — install, run `akasha setup`, vault
  your first credential, and wire up an agent.
- **[Threat Model](THREATMODEL.md)** — what Akasha defends, what it doesn't, and
  where the trust boundary sits. Read this before reporting a vulnerability —
  several behaviours are by design.

## Plugins — integrate any login as data

No provider is compiled in; a login is a YAML file (a *protocol*, not a service).

- **[Write a Plugin](writing-a-plugin.md)** — the short tutorial: a Datadog
  example, then `validate → explain → trust → use`.
- **[Plugin Format](PLUGIN_FORMAT.md)** — the complete reference: the
  `credential` / `discover` / `deliver` / `own` / `source` blocks, the
  fixed daemon primitives a plugin selects by name, and the trust & signing model.

## Policy — control how secrets are accessed

- **[Local Retrieval Policy](POLICY.md)** — the `~/.akasha/policy.yaml` reference:
  the **use-vs-read** model (brokered use allowed, raw reads denied), matchers,
  `allow` / `deny` / `ask`, fail-closed approval, and the seamless default that
  ships with `akasha policy init`.

## Operations

- **[macOS Signing](macos-signing.md)** — sign local builds with a stable
  identity, because launchd will not run an unsigned daemon at all. (Signing
  does *not* gate access to your vault key; that note explains why.)
- **[Security Policy](../SECURITY.md)** — how to report a vulnerability.

## At a glance

| I want to… | Read |
|---|---|
| Install and take the first steps | [getting-started.md](getting-started.md) |
| Integrate a new service (a login) | [writing-a-plugin.md](writing-a-plugin.md) |
| Look up a plugin field or mechanism | [PLUGIN_FORMAT.md](PLUGIN_FORMAT.md) |
| Control who can access what | [POLICY.md](POLICY.md) |
| Understand the security guarantees | [THREATMODEL.md](THREATMODEL.md) |
| Build from source on macOS | [macos-signing.md](macos-signing.md) |
