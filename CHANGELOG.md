# Changelog

All notable changes to Akasha are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha.3] - 2026-08-13

Policy-engine hardening. An adversarial review of the shipped engine found that
its evaluation logic was sound but its **inputs were attacker-controlled**:
`policy.Request` mixed server-derived facts with caller-asserted claims in one
flat struct, and the matcher could not tell them apart.

**If you are running the starter policy from `akasha policy init`, you were
affected.** Upgrade, then run `akasha policy validate` — it names the obsolete
rule and anything else that needs attention.

**Rotate your agent keys.** `akasha agent list` printed them in full until this
release, so treat any key that existed before upgrading as disclosed:
`akasha agent resync <client> --rotate`. Note that repeated `akasha setup` runs
also left older keys active — `akasha agent list` shows every one, and each is
still valid until revoked.

### Security

- **Raw secret reads were reachable by claiming the broker's name.** The starter
  policy permitted the credential helper with `action: retrieve` +
  `tool: akasha_helper`, above a blanket `retrieve → deny`. `requesting_tool` is
  a free-text request-body field, so writing that one string returned decrypted
  plaintext. No shell was required: `requesting_tool` is an ordinary argument of
  the `vault_retrieve` MCP tool, so a prompt-injected agent could do this from
  its normal tool surface.

  The helper no longer names itself — it resolves through `/resolve`, which the
  daemon labels. Brokered use has its own server-assigned action (`broker`), the
  `akasha_*` tool namespace is refused in request bodies, and the exception rule
  is gone from the starter policy.

- **Any `provider:`/`instance:` rule could be walked past with an alias.**
  Labels are not unique per secret, so binding a second name to a vaulted
  credential and requesting it under that name matched a provider nobody wrote a
  rule for. Reads now evaluate against **every** name a secret answers to and
  deny if any is denied; legitimate aliases keep working.

- **The write side was ungated.** `/label/set`, `/put`, `/profile/save` and
  `/vault/purge` had no policy check, so an agent could re-point `aws:default` at
  credentials it controlled and the next credential-helper call would
  authenticate as the attacker. New `bind` and `purge` actions; re-pointing an
  existing label is classified `critical` (a new label is `high`) so `min_risk`
  can single it out.

- **Asserted identities can no longer satisfy an `allow`.** `agent:` and `tool:`
  were documented as advisory but nothing enforced it. They may now narrow a
  `deny` or `ask`, never grant. Identities the daemon assigns itself
  (`akasha-helper`, `akasha-list`, …) are unaffected — those endpoints ignore
  the request body, so the names cannot be claimed.

- **Every route pins its HTTP method** (405 + `Allow`). No handler validated the
  verb, so `<img src="http://127.0.0.1:7743/vault/purge">` on a web page reached
  a destructive endpoint: a subresource GET carries a loopback `Host` and no
  `Origin`, which the DNS-rebinding guard permits by design.

- **Agent keys were recoverable from the vault.** `key_id` *was* the bearer key,
  so `akasha agent list` printed every live credential — ten-plus on a typical
  install, total impersonation of any agent in one command. `key_id` is now a
  non-secret handle derived from the key's hash; the key itself exists only in
  the output of `akasha agent create`. Existing rows are migrated on first open,
  and live keys keep working. `akasha agent revoke` now takes the handle, so
  revoking no longer means pasting a bearer secret into your shell history.

- **An agent could classify a secret out of policy's reach.** `risk` was a
  free-text field on `/store`, which is not policy-gated, and the engine ranked
  an unrecognised level *below* every threshold. Storing a secret as `criticall`
  — one typo from a real level — made it invisible to every `min_risk` rule and
  fell through to `default: allow`. `/store` now rejects a risk it cannot rank,
  and unrankable risk makes restrictive rules apply rather than skip.

- **The audit log listed live vault tokens.** Hundreds of them, in cleartext —
  the enumeration primitive the bypasses above needed. Tokens are now recorded as
  a stable digest, which preserves the correlation the log actually used them for
  while being useless as a credential. Free-text fields (`task`,
  `reasoning_trace`, `triggered_by`) are swept too, so an agent cannot log its
  own tokens by putting them in a task description.

- **Deleting `policy.yaml` silently disabled the engine.** The next request was
  allow-all, with no log line, and a warm restrictive policy gave no protection
  because the missing-file check ran before the cache. The daemon now remembers
  that a policy was installed: a missing file fails closed and is audited, while
  a machine that never had one still allows everything. `akasha policy disable`
  is the deliberate off-switch. Policy load, change and disappearance are now
  audited — previously the control could be turned off without a trace.

- **The approval dialog was written by the caller.** Newline escaping rendered as
  real line breaks, so `task` or `requesting_tool` could forge convincing
  `Risk:` / `Tool:` lines — and `Tool` rendered *above* `Task`, placing forgeries
  above the genuine text. Control characters are now stripped rather than
  escaped, server-derived facts print first, caller-supplied text is labelled
  unverified, the secret is named (two prompts used to be indistinguishable), and
  every field is capped so a long value cannot push the buttons off screen.
  Approvals are serialised, so a flood of concurrent requests can no longer stack
  dialogs until one is approved.

### Added

- **`akasha run`** — supervised launch. Runs an agent inside an OS sandbox
  (macOS seatbelt, Linux bubblewrap) where the vault, the OS keychain,
  materialized session credentials and your plaintext credential files are
  unreachable, under a per-run identity that may broker only the credentials you
  name and whose access is revoked the moment the supervisor exits. Enforcement
  is proved on every launch (~55ms) rather than assumed. It does **not** confine
  the network, so exfiltration is unaddressed, and it does not defend against
  prompt injection — see [THREATMODEL](docs/THREATMODEL.md#enforcement-ladder-honest-positioning).
- **`akasha setup --yes`** for unattended installs. Trusts the shipped provider
  bundle only — never a template you dropped in — and refuses to fake a key
  backup, which needs a passphrase.
- **`akasha version`** / `--version`. A security release is only actionable if
  you can tell whether you are on it.
- **`sandbox:` policy matcher**, so a rule can *require* a supervised launch:
  `{action: broker, provider: aws, instance: prod, sandbox: false, effect: deny}`.

### Changed

- **Policy cache keys on file content, not `(mtime, size)`.** The old cache
  captured the stat *before* reading, so restoring a file padded to the same
  length with a copied mtime left the daemon enforcing a policy that `cat` and
  `akasha policy validate` both disagreed with.
- **Unrankable risk now satisfies `min_risk` on `deny`/`ask`** (and still does
  not on `allow`). If you relied on unclassified entries slipping past a
  restrictive rule, they no longer do.
- **Glob matching no longer uses `filepath.Match`.** `*` now matches any run of
  characters **including `/`**, `?` matches exactly one character, and every
  other character — `[`, `]`, `\` included — is literal. If you relied on
  `[abc]` character classes (an undocumented side effect of the old
  implementation), they are now literal text. There is also no longer any such
  thing as an invalid pattern, so a typo can no longer silently disable a rule.
- **New policy actions:** `broker`, `bind`, `purge`. `action: retrieve` no longer
  covers the credential helper — it is `broker` now.
- Allow rules keyed on `agent:` or `tool:` grant only to callers presenting a
  valid agent key. `akasha policy validate` lists any such rule; if one stops
  taking effect, the caller is almost certainly missing its key
  (`akasha status`, `akasha agent resync <client>`).

### Fixed

- **The documented escrow gating rule never fired.**
  `{provider: escrow, instance: "*"}` could not match, because escrow instances
  are absolute paths and the old `*` stopped at `/`. It read as "approve every
  escrow read" and silently matched nothing.
- **The documented lockdown posture denied your own CLI.** Under `default: deny`
  with only `agent: claude` rules, a keyless `akasha list` arrives as
  `akasha-list` and matched nothing — so `list`, `restore`, `put`, `inspect`,
  `discover` and `setup` all failed. The example now allows the daemon-assigned
  identities explicitly.
- **The server test suite was not isolating the policy engine.** It seeded a
  temp vault and audit log but left the daemon reading the developer's real
  `~/.akasha/policy.yaml`, so results depended on machine state — three tests
  failed on a clean checkout and one hung for 60s on a GUI approval dialog. This
  is why the policy path went untested and the bypasses above survived review.

### Docs

- `docs/POLICY.md`: documents the glob syntax, the alias-union rule, the action
  table, and which matchers are trustworthy and why. Corrects the claim that
  there is no path to a secret that skips the policy gate — direct vault access
  (`akasha vault`, `akasha agent`) does not go through the socket, and a process
  holding your UID can edit `policy.yaml`.

## [0.1.0-alpha.2] - 2026-07-29

### Changed
- **Seamless-broker default policy — no more routine approval popups.** The
  starter/default policy allows brokered *use* (the git/AWS credential helper)
  and gates only raw reads and high-risk grants, instead of asking on every
  assume. The guarantee is unchanged: a raw `vault_retrieve` is still denied.
- **Multi-provider git ownership merges into one gitconfig.** GitHub and GitLab
  can broker in the *same* session — both host-scoped `[credential …]` sections
  land in one `GIT_CONFIG_GLOBAL` file instead of colliding. GitLab now ships an
  ownership block. Daemon-side rendering only; no format change.
- **Install hosts prebuilt binaries on the getakasha.dev CDN** while the repo is
  private, so `curl -sSL https://getakasha.dev/install | sh` resolves binaries
  without a public GitHub release.

### Docs
- Plugin format documented as one stable reference: a **frozen core + additive
  named-mechanism** extension. The general "config as data" ownership engine is
  **deliberately deferred** (it would be a standing command-injection surface);
  ownership extends by adding a small reviewed mechanism.
- Added a docs index; documented the policy engine's **use-vs-read** model and
  the seamless-broker default.

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

[0.1.0-alpha.2]: https://github.com/inferlabshq/akasha/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/inferlabshq/akasha/releases/tag/v0.1.0-alpha.1
