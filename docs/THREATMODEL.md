# Akasha Threat Model

This document states what Akasha defends, what it does **not**, and where the
trust boundary sits. Read it before reporting a vulnerability — several
behaviours below are **by design**, not bugs (see [§ Out of scope](#out-of-scope-by-design)).

Status: **alpha**. Local-only; no cloud component. Treat it as alpha software —
do not protect secrets you cannot rotate.

## What Akasha is

A local daemon that holds a user's credentials in an encrypted vault and hands
**agents** (AI coding tools) short-lived, audited access — so the agent acts
with a credential without ever holding the raw long-lived secret. Integrations
are **plugins**: data-only YAML files describing how a provider's credentials
are shaped, discovered, fetched, delivered, and (optionally) used to route an
agent's tooling through the daemon.

## Assets

- The vaulted secrets (`~/.akasha/vault.db`, XChaCha20-Poly1305; key wrapped with
  ML-KEM-768 in the OS keychain).
- The audit log (what was accessed, by which agent, and why).
- The integrity of the agent's credential path (that an agent gets *its* scoped
  credential and nothing more).

## Actors

| actor | trusted? |
|---|---|
| The user (local human) | trusted |
| The daemon + OS keychain | trusted (the TCB) |
| A **plugin** dropped in `~/.akasha/templates/` | **untrusted until signed-by-a-trusted-publisher or explicitly approved** |
| An agent's tool-call content / observed data | untrusted (data, never instructions) |
| A signing **publisher** the user has trusted | trusted (for what they sign) |
| An external secrets-manager backend (e.g. `op`) | trusted as configured by the user/operator |

## The trust boundary

The central rule: **an untrusted plugin is inert.** Merely dropping a YAML in
the templates dir and having the daemon load it grants it nothing dangerous.

| effect | requires |
|---|---|
| be parsed / loaded | nothing (parse is data → known Go structs; no code) |
| read-only discovery (`discover:`) of declared paths | runs on `discover`/`setup` (see known limitation below) |
| **materialize a credential into a session** (`deliver:` file/env) | **trust** (signature or `template trust`) — capability `deliver`; the rendered file name is contained to the session dir, and env values (which can execute code, e.g. `GIT_SSH_COMMAND`) apply only for a trusted template |
| deliver on-demand (`deliver: helper`) / read an already-vaulted credential | the credential vaulted; governed by the **policy gate** (no system-modifying effect → no template-trust) |
| **run a source backend** (`source:`) | **trust** (signature or `template trust`) — capability `run-backend` |
| **own an agent session's env** (`agent.own`) | **trust** (signature or `template trust`) — capability `own-agent-env` |

Trust is conferred two ways, unified in the daemon:
1. a valid **signature** from a publisher the user trusts (the embedded official
   key, or one added via `akasha publisher add`), verified against the file's
   bytes — editing the file breaks the signature; or
2. an explicit **`akasha template trust`**, bound to the file's SHA-256 — editing
   the file revokes the approval until re-approved.

## Defences (what we guarantee)

- **Secrets at rest.** XChaCha20-Poly1305 vault; key in the OS keychain, never on
  disk. Session credential files are RAM-backed (tmpfs / macOS RAM disk) and
  TTL-swept, so they never touch the SSD.
- **Untrusted plugins can't execute code or own the environment.** Both effects
  are gated by the trust mechanism above.
- **No command injection via ownership.** `agent.own` selects a named protocol
  *mechanism* (credential-process, git-credential-helper, decoy); the command
  written into the generated config is rendered in Go and is *always* the akasha
  binary. A plugin supplies only charset-validated structural params — there is
  no field in which to place a command.
- **The agent path brokers a secret; it does not hand one over.** When a
  *verified agent* assumes a provider whose delivery would materialize the secret
  *itself* into an env var (a raw `GITHUB_TOKEN`, or the generic `env:` fallback),
  the daemon refuses and points at the broker instead. `akasha exec --assume`
  applies the provider's declared `agent.own` mechanism, so the child's tooling
  resolves the credential through `akasha helper` **per operation** — e.g. `git`
  calls back on every fetch/push and the token never enters the environment. A
  materialized env/file delivery stays available on the local-human path (plain
  `akasha exec`, for a tool that can only read a fixed env var), but the agent
  holds a callback, not the secret.
- **Constrained backend execution.** A `source` backend runs via
  `exec.Command(bin, args...)` (no shell); the template-supplied reference is one
  argv element after `--` (no flag/command injection); the binary is the
  backend's fixed name (operator-overridable only via an absolute-path env var,
  never template-chosen); the subprocess environment is the backend's allowlist
  only (no daemon env, other secrets, or `AKASHA_*` keys); execution is
  time-bounded and output-capped.
- **Audited access, without silent loss.** Every retrieval/broker is recorded
  with agent identity, tool, and the task/reasoning provenance captured at the
  moment of access. The logger applies backpressure rather than dropping under a
  burst (an event is never silently lost to a full buffer), surfaces write/fsync
  errors instead of swallowing them, and fsyncs periodically for crash-durability.
  The append-only log is size-rotated with bounded retention so it cannot grow
  until the disk fills; each rotation and prune is logged.
- **No browser can reach the daemon.** The always-on TCP loopback listener is
  wrapped in a host guard: a request whose `Host` is not loopback is refused
  (defeating DNS rebinding, where a malicious site re-resolves its domain to
  127.0.0.1), as is any request carrying a non-loopback `Origin` (cross-origin
  browser fetch/POST). Browsers cannot open the Unix socket, so it is exempt.
  Metadata endpoints (`/inspect`, `/label/list`) also pass the policy gate, so a
  `default: deny` policy withholds the inventory as well as the secrets;
  `/health` remains an unauthenticated liveness probe exposing only vault counts.
- **No arbitrary-exec backend** exists, by design.

## Enforcement ladder (honest positioning)

Akasha's protection comes in tiers, and we are explicit about what each one can
and cannot promise. An agent runs as your user with a shell: **no
configuration-level mechanism (MCP config entries, env injection, harness
hooks) is bypass-proof against a determined adversary** — anything installed by
writing config can, in principle, be un-configured or side-stepped by a process
with the same privileges. What each tier actually delivers:

1. **Possession** — a secret stored *only* in the vault (agent-stored secrets,
   and any file escrowed with the opt-in `akasha protect`) is unreachable
   except through the daemon socket, which authenticates, audits, and (with
   the policy engine) gates every retrieval. This is the strongest guarantee
   Akasha makes: there is no plaintext to steal, so bypassing the interception
   layers gains nothing. `discover` alone vaults **copies** — originals stay
   on disk until you escrow them; `akasha restore` (and `akasha uninstall`,
   automatically) puts them back byte-for-byte.
2. **Environment ownership** — `agent.own` mechanisms (credential-process,
   git-credential-helper, decoys, session env) put Akasha on the *default* path.
   This governs well-behaved and casually-misbehaving agents; it is drift
   protection, not adversarial enforcement.
3. **Supervised launch** (`akasha run`, alpha — macOS + Linux) — the agent runs
   inside an OS sandbox where the vault, the OS keychain, materialized session
   credentials and the well-known plaintext credential files are unreachable,
   under a per-run identity whose credentials are revoked the moment the
   supervisor dies. The daemon enforces broker-only for that identity: raw
   reads, materialization, inventory and delegation are refused outright, and
   only the `--assume` grants may be brokered.

   What this tier does NOT do, and must not be described as doing: it does not
   confine the **network**, so a compromised agent can still exfiltrate what it
   is allowed to broker; it does not fix **prompt injection**, which corrupts
   the operation rather than the reach; and a process inside the sandbox can
   still read the plaintext of a credential it is permitted to use — the
   guarantee is that the secret is never materialized into the session and
   every use is audited, not that the value is unreachable from inside.

   It is also **containment, not identity**: the daemon distinguishes a run by
   the listener a request arrived on plus a bearer key, so an adversary holding
   both the run socket path and that key could present as sandboxed. Stronger
   than anything caller-asserted; not a cryptographic boundary.

**Payload classification is advisory.** Sensitive data that originates inside
an agent session (e.g. pasted into a prompt) was never Akasha's to vault;
classifiers over tool-call content reduce accidents, they do not guarantee
containment below tier 3. We will not market them otherwise.

## Out of scope (by design)

These are **not** vulnerabilities. Reports of them will be closed as by-design.

- **A *trusted* plugin runs code.** That is what trust means. Trusting a
  malicious plugin, or adding a malicious publisher key, is equivalent to
  installing a malicious package — game over, and the user's choice. The boundary
  Akasha defends is *untrusted → inert*, not *trusted → harmless*.
- **A trusted ownership plugin routes a tool through the akasha helper for a
  host/profile of its choosing.** Within trust, that is expected; the helper only
  ever serves vaulted credentials through the audited daemon (it is not RCE).
- **A fully compromised host.** Root/malware on the machine, a compromised OS
  keychain, a debugger attached to the daemon, etc. A local vault cannot defend a
  machine the attacker already owns.
- **The user reading their own secrets.** Akasha gates *agents*, not the human
  who owns the vault.

## Known limitations (alpha — being hardened)

Disclosed deliberately so they are not reported as surprises. All are tracked for
hardening before a stable release:

- **Backend subprocesses run with the user's privileges** — there is no OS
  sandbox (seccomp/landlock/sandbox-exec) around a `source` backend yet. A
  *trusted* backend is therefore unconfined. (Planned.)
- **Backend binary resolution can still use `$PATH`.** World-writable binaries
  and directories are now refused (the PATH-hijack vector), but a non-world-
  writable PATH entry is still trusted; pin an absolute path with
  `AKASHA_<BACKEND>_BIN` for full assurance.
- **A *trusted* discovery template reads the paths it names.** Untrusted
  discovery is no longer run at all (it's gated by `CapReadFiles`), and
  parent-dir traversal is refused; but a template you have *trusted* can still
  read the (non-traversal) file paths it declares, which can include credential
  files under your home. That is within trust, by design.
- **Agent identity is a bearer key, not attestation.** The per-agent API key
  lives in the agent's session environment / client config, so any same-user
  process — including another agent — can read it and impersonate that agent
  to the daemon. Per-agent policy rules are therefore drift protection, not
  adversarial enforcement, until agents run isolated (the planned
  `akasha run` sandbox, where identity is the sandbox itself). Enterprise
  deployments with real workload selectors (k8s, dedicated UIDs) will get
  SPIFFE/SVID validation as an alternative identity source; it is deliberately
  not required — or useful — on a single-user machine. The same bearer-key
  signal gates the agent-facing raw-secret-env refusal (see Defences): the
  daemon withholds a materialized secret from a *verified agent*, but a same-user
  process that simply presents **no** agent key is treated as the local human and
  takes the materializing path. The refusal is therefore drift protection against
  a well-identified agent, not an adversarial barrier — tier-3 isolation (where
  the sandbox *is* the identity) is what makes it mandatory. For the full
  analysis — why a better token can't fix this, the rungs that can (peer
  code-signature attestation, dedicated UIDs, sandbox, per-vend presence), and
  the prompt-injection ceiling none of them cross — see
  [Design: the same-user agent-identity problem](design/same-user-identity.md).
- **The policy file is a local file, not attested.** `~/.akasha/policy.yaml` is
  0600 and user-writable, so a same-user process can edit it and the next
  operation is evaluated against the edit. The daemon now records the digest of
  each policy it loads, so **deleting** the file fails closed and is audited
  (`POLICY_MISSING`) rather than silently reverting to allow-all — and load,
  change and disappearance all appear in the audit log. That converts a silent
  kill switch into a loud one; it does not make the file tamper-proof, which is
  the same class of gap as the trust store below.
- **Vault tokens are still cleartext in `vault.db`.** As of 0.1.0-alpha.3 the
  audit log records a stable digest instead of the token, so reading the log no
  longer hands an attacker a list of live credentials to try. The database still
  stores tokens as a primary key, so this closes the casual path — a readable
  log — not on-box enumeration by something that can read the DB. Possession
  (tier 1) is what makes the token useless without the daemon.
- **MCP client keys are passed in `argv`.** `akasha setup` writes
  `akasha mcp --agent-id X --api-key agt_…` into each client's config, so the key
  is visible in `ps` for the lifetime of the MCP server. The vault no longer
  stores agent keys in recoverable form, but this delivery path is unchanged;
  moving to env/fd alters the MCP client contract and is queued with the work to
  move MCP off its hardcoded TCP endpoint.
- **The trust store is a local file, not attested.** Template approvals live in
  `~/.akasha/approvals.json` (0600) and are each bound to the file's SHA-256, but
  the store itself is user-writable — a same-user process (e.g. a compromised or
  prompt-injected agent with shell access) could forge an approval record for its
  own malicious template. This is the same class of gap as the bearer-key
  limitation above: template trust defends against an untrusted plugin arriving by
  a *weaker* vector (a downloaded, synced, or agent-dropped file the attacker did
  not also get to approve), not against a full same-user compromise. The vault
  *key* is already protected by the OS keychain ACL (only the code-signed daemon
  can use it); the planned hardening is to give approvals the same footing —
  signing each record with a keychain-held key so a forged record fails an
  integrity check, and/or gating approval behind a presence check (Touch ID /
  Windows Hello). Until then, approval is an explicit CLI/`setup` action writing a
  plain JSON record — not itself keychain- or biometric-backed.
- **Bounded audit retention vs. an unbounded flood.** The audit log never drops
  events silently and is size-rotated with bounded retention, but a finite disk
  cannot hold infinite history: under a *sustained adversarial flood* the oldest
  rotated segments are eventually pruned. This is not a silent loss — the flood
  itself is fully audited (a burst of events is loud evidence), and every prune
  is logged — but very old pre-flood records can age out. Raising
  `AKASHA_AUDIT_KEEP` / `AKASHA_AUDIT_MAX_SIZE`, and (planned) rate-limiting plus
  off-host shipping, widen the window.
- **No cloud/remote component** — the audit log is local only.

## Reporting

See [SECURITY.md](../SECURITY.md). When in doubt about whether something is
in-scope, check the boundary above: does it let an **untrusted** plugin execute
code, own the environment, exfiltrate a secret, or read the vault? If so, it's a
vulnerability — please report it.
