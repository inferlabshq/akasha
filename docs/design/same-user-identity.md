# Design note: the same-user agent-identity problem

**Status:** design / roadmap framing. Rungs 1–4 are not shipped; the
privilege-inversion corollary below **is** fixed (rung 0.5). Companion to the
[Threat Model](../THREATMODEL.md) — this note expands the "known limitation"
that agent identity is a bearer key into *what a real fix would take*, so the
ordering of the roadmap rungs is defensible and the ceiling is stated honestly.

## The problem

Akasha's daemon runs as the user. Agents (Claude Code, Codex, Cursor, …) run as
the **same user**. An agent authenticates with a bearer key (`AKASHA_AGENT_ID` /
`AKASHA_AGENT_KEY`) carried in its session environment, and the daemon
attributes a request to that key. The local human is an identity too — the
reserved `cli` key the daemon provisions at startup
(`daemon/internal/clikey`); a request carrying no key at all is refused.

That makes per-agent policy **drift protection, not adversarial enforcement**. A
same-user process can:

- read another agent's key from its env (`/proc/<pid>/environ`) or client config
  and impersonate it;
- read the human's own `cli.key` (0600, but same-uid) and act as the human;
- reach the daemon socket directly and issue well-formed calls.

### The corollary: revocation was bypassed by presenting *less* — FIXED

**Status: fixed.** Kept here because the shape of the mistake is worth
remembering, and because what the fix does *not* buy needs stating.

Authentication used to **reduce** privilege. A verified agent was refused the
providers whose delivery materializes a raw secret into an environment variable
(the old `isVerifiedAgent` gate in `daemon/internal/server/server.go`); a caller
presenting no key was not. So the keyless path was not merely *as* privileged as
a valid key — it was *more* privileged. Reproduced by hand:

```
$ AKASHA_AGENT_KEY=<revoked> akasha whoami aws:pk-website
denied: agent key has been revoked
$ unset AKASHA_AGENT_KEY && akasha whoami aws:pk-website
<identity for every AWS credential in the vault>
```

`akasha agent revoke` therefore removed an **identity** without closing an
**access path**, and the rational move for any local process was never to
authenticate at all.

The fix makes privilege **monotonic in authentication** — presenting less can
only ever get you less:

- **Every caller authenticates.** A request with no `X-Akasha-Key` is refused
  (401) on every endpoint but `/health`. Dropping the header now lands on the
  floor rather than the ceiling.
- **The human CLI has a real identity.** The daemon mints a key for the reserved
  identity `cli` at startup and writes it 0600 as `cli.key` in the vault's data
  directory. The human path is granted on an affirmative identity instead of on
  an absence the daemon has no way to verify.
- **Reserved identities cannot be minted by a caller.** `agent create cli` and
  `agent create run:*` are refused in the *vault* layer rather than the HTTP
  layer, because `agent create` opens the vault directly and never touches the
  socket.
- **The CLI will not perform the upgrade on an agent's behalf.** A session with
  `AKASHA_AGENT_ID` set but no key is refused rather than silently falling back
  to `cli.key`.

Regression tests: `daemon/internal/server/revocation_test.go`,
`daemon/internal/clikey/clikey_test.go`,
`daemon/cmd/akasha/callerkey_test.go`.

**What this does not buy.** `cli.key` is readable by the user's own uid, and
agents run as that uid — so a local process that reads it can still act as the
human. That is the theorem below, untouched. What changed is that impersonation
now requires stealing a specific, revocable, auditable credential rather than
being the reward for sending one fewer header. The environment check in the CLI
is drift protection and is defeated by `env -u AKASHA_AGENT_ID`; the daemon's
keyless refusal is the real boundary, and it too stops at the same-UID ceiling.

So this is rung 0.5, not rung 1. Containment still comes from rung 3
(`akasha run`), not from the key registry, and `akasha agent revoke` should keep
saying so.

A rogue-but-well-formed broker call is a **different threat** from command
injection. Command injection (turning the broker into arbitrary code execution)
is prevented — fixed allowlisted binary, no shell, `--` guard, scrubbed env,
trust gate (`daemon/internal/resolve/resolve.go:94`, `:45`, `:95`;
`daemon/internal/resolve/backend_onepassword.go:31`;
`daemon/internal/server/server.go:925`). The same-user vend is a legitimate call
by an illegitimate caller. This note is about *that*.

## The theorem

> You cannot establish trustworthy identity of a **same-UID peer** using a
> secret that lives in that peer's same-UID-readable memory or environment.

Any bearer credential is forgeable by a same-user adversary — read its env, read
its config, or `ptrace` the process and become it. So the fix is **never a
better token**. It is to change *what establishes identity*: move it from
"asserted at call time by the untrusted caller" to "established out-of-band by
the trusted party (the daemon or the OS)." Every real fix below is a variation
on that one move.

There are two families: attest *who* is calling (Family 1), or move *authority*
to a signal no same-user software can forge (Family 2). They are complementary.

---

## Family 1 — move identity to an OS-enforced boundary

### 1a. Peer code-signature attestation  (recommended next rung; macOS)

Akasha already serves over a unix socket. On macOS the daemon can read the
peer's **audit token** (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`) and verify the
connecting process's code signature via `SecCodeCopyGuestWithAttributes` +
`SecCodeCheckValidity` — checking Team ID / cdhash against an allowlist. A rogue
process cannot forge a signature whose signing key it does not hold.

- **Defeats:** the "random same-user script or unsigned malware calls the
  broker" case entirely. The caller must now *be* a signed, allowlisted binary.
- **Precedent in-tree:** this is the same principle already enforced one layer
  down — the vault key is protected by a keychain ACL so *only the code-signed
  daemon* may use it. Peer attestation extends "who may use the key" to "who may
  call the daemon."
- **Fits the existing trust model:** maintain an allowlist of trusted client
  cdhashes (Claude Code, Cursor, …) with a `template trust`-style escape hatch
  for a user's self-built agent — symmetric with the publisher/approval model.
- **Limit:** attests the *binary*, not the *logical agent*. Two instances of the
  same signed client share a cdhash and are indistinguishable. Does nothing for
  a hijacked-but-signed agent (see [The ceiling](#the-ceiling)).
- **Linux:** no base-OS equivalent. Requires dedicated UIDs, LSM domains
  (SELinux/AppArmor), or IMA measured binaries — all enterprise-grade, not
  laptop-default.

### 1b. Dedicated UID per agent

Run each agent as its own OS user. Then `SO_PEERCRED` UID *is* real identity and
`0600` file permissions actually separate agents.

- Theoretically the cleanest non-sandbox answer.
- This is what enterprise gets "for free" from k8s workloads / dedicated service
  accounts — hence the threat model routes fleet deployments to SPIFFE/SVID.
- **Impractical on a single-user laptop** (user provisioning, sudo, permission
  gymnastics); natural in a fleet.

### 1c. Daemon-launched sandbox  (tier 3 — the endgame)

The daemon *creates* the sandbox, so it knows the sandbox's identity out-of-band;
the socket / credential is reachable **only** from inside that sandbox. Identity
becomes the boundary the trusted party built, not a token the agent asserts.

- The only rung where "mandatory" is literal — bypassing interception gains
  nothing because there is no reachable plaintext and no forgeable in-band
  identity.
- This is the correct terminal answer; everything else is a lower rung that buys
  real value before it ships. Tracked as `akasha run` in the roadmap.

### 1d. PID-bound leases

Issue a credential lease bound to the peer-cred PID and refuse it from any other
PID.

- Narrows the window: a rogue process would have to *be* the agent's PID.
- **Defeated by `ptrace`** on Linux where same-user attach is permitted (unless
  `kernel.yama.ptrace_scope` is raised system-wide).
- **Meaningfully stronger on macOS**, where hardened-runtime binaries resist
  being debugged — so PID binding + hardened runtime is a real barrier there.

---

## Family 2 — move authority to an unforgeable signal

### 2a. Per-vend human presence

Gate sensitive vends behind **Touch ID / Windows Hello / a hardware key**
(LocalAuthentication on macOS). This does not identify the agent — it makes the
*authority* something a background rogue process physically cannot produce,
converting "silent same-user theft" into "requires a human touch."

- The threat model already floats this for the trust store; it generalizes
  cleanly to vends.
- **Cost:** friction. Scope it to `critical` / policy-`ask` credentials, not the
  seamless broker path.
- Strongest same-user answer that needs no per-agent isolation.

---

## The ceiling

None of the above defends a **legitimately-signed, correctly-identified agent
that has been prompt-injected.** Every identity mechanism confirms "yes, that is
really Claude Code" — because it is; it is executing attacker-supplied text.
Attestation attests *code, not intent*.

That class is a **different axis**, addressed only by:

- **least-privilege / scoped short-lived credentials** so a successful vend is
  worth less. A `mint` block was drafted for this and **removed from the format
  before v1**: it validated and printed but never executed, and an unimplemented
  name freezes as public API at the first tag. Graceful degradation now lets an
  older daemon drop a primitive it does not implement, so re-adding `mint` with
  its implementation costs nothing — the capability is deferred, not abandoned;
- **per-operation human approval** for high-value credentials (Family 2 again);
- **audit / detection** — the vend is loud even when authorized
  (`daemon/internal/server/server.go:897-915`).

Identity attestation and behavioral containment are orthogonal. Solving one does
not solve the other, and the sandbox does **not** fix prompt injection. State
this plainly wherever the identity story is told.

---

## Recommended ordering for Akasha

Cheapest real rung first; each buys value before the next ships.

| Rung | Mechanism | Buys | Limit |
|---|---|---|---|
| 0 | Policy + allow/deny/ask (shipped) | Drift protection + audited detection; gateable to fail-closed ask | Bearer identity is forgeable |
| 0.5 | **Mandatory authentication + a real `cli` identity (shipped)** | Privilege is monotonic in authentication; revocation can no longer be undone by dropping the header | `cli.key` is same-uid readable, so the human is still impersonable |
| 1 | **Peer code-signature attestation (macOS)** | Rejects non-attested rogue callers; mirrors keychain-ACL precedent | Binary-level, not per-instance; no Linux base-OS analog |
| 2 | **Touch ID per critical vend** | Kills *silent* same-user theft for high-value creds | Friction; scoped to gated creds |
| 3 | **Daemon-launched sandbox (`akasha run`)** | True logical identity; "mandatory" becomes literal | Larger build; the real endgame |
| 4 | **Dedicated-UID / SPIFFE** | The fleet/enterprise identity story | Impractical on a single-user laptop |

**Honest caveat to carry everywhere:** rungs 1–3 are macOS-first. The
cross-platform same-user problem has no clean laptop-level answer outside the
sandbox (rung 3); on Linux the intermediate rungs require enterprise-grade
isolation (dedicated UIDs, LSM domains, IMA) that a default developer machine
does not run. Do not imply platform parity.

## One-line summary

Policy is rung 0, not the ceiling. Real fixes exist — attest the caller (code
signature, dedicated UID, sandbox) or move authority to human presence — but a
better *token* is not among them, and none of them defend a prompt-injected
*legitimate* agent, which is a separate problem solved by least privilege,
human-in-the-loop, and detection.
