# Changelog

All notable changes to Akasha are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha.1] - 2026-07-29

First public alpha.

### Added — plugin platform
- **No compiled-in providers.** AWS, GitHub, and any service are data-only YAML
  plugins loaded from disk through one uniform path; the curated bundle ships as
  data, and a user file can override any of it. (`docs/PLUGIN_FORMAT.md`)
- **Authoring loop:** `akasha template validate | explain | list | new` — explain
  prints a capability manifest + a dry run with placeholder secrets.
- **Trust gate:** high-trust effects (owning agent env, running a backend,
  reading files) require a hash-bound `akasha template trust` or a valid
  signature; an untrusted plugin is inert.
- **Signing + marketplace:** Ed25519 plugin signing (`akasha keygen`,
  `template sign/verify`) and trusted publishers (`akasha publisher add/list/
  remove`) — trust an author once and their signed plugins are auto-approved.
- **Source resolvers (alpha):** broker a credential live from an external
  secrets manager (1Password) — `source:` block + on-demand mode; wired into
  `assume` and the credential_process/git helper so agents get brokered secrets.
- **Structured ownership mechanisms:** `agent.own` selects a protocol mechanism
  (credential-process / git-credential-helper / decoy); the command is always
  the akasha binary.
- Tutorials: `docs/getting-started.md`, `docs/writing-a-plugin.md`.

### Security
- **The agent never receives a raw secret.** The agent-facing assume/retrieve
  path refuses to materialize a secret into an env var; git/GitHub/AWS route
  every operation through the `akasha helper` broker instead, so the token
  reaches the tool, never the agent's context. `akasha exec --assume` applies a
  provider's declared broker per-operation.
- **Policy engine — USE vs READ.** `~/.akasha/policy.yaml` (hot-reloaded) allows
  brokered *use* (credential helper) and denies raw *reads* into an agent's
  context; assume/grant handoffs can require human approval.
- **Stable code-signing (macOS).** `install.sh` signs local builds with a
  per-machine self-signed identity so the vault-key keychain ACL survives
  updates; release binaries can be Developer ID-signed + notarized.
  (`docs/macos-signing.md`)
- **Ownership command-injection (RCE) closed:** ownership config is Go-rendered
  from charset-validated structural params — no template-supplied command.
- **Backend PATH-hijack hardening:** world-writable binaries/dirs are refused;
  `AKASHA_<BACKEND>_BIN` must be absolute.
- **Discovery gated:** file-reading discovery runs only for trusted templates;
  parent-dir traversal in declared paths is refused.
- **No arbitrary-`exec` backend.** Removed; trimmed the backend enum to what is
  implemented.
- Added `SECURITY.md` and `docs/THREATMODEL.md`.

### Foundation (pre-plugin-platform)
- Go daemon: vault (XChaCha20-Poly1305 + ML-KEM-768, key in OS keychain,
  RAM-backed session files), classifier, audit log, MCP server, Python SDK.
- `akasha setup`, credential discovery (AWS/SSH/git), `assume`/`exec`,
  A2A cross-agent grants.

[0.1.0-alpha.1]: https://github.com/inferlabshq/akasha/releases/tag/v0.1.0-alpha.1
