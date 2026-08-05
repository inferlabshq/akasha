# Launch objections — code-cited answers

Ready-to-paste answers for the hard questions a Show HN / security audience will
ask. Every claim is tied to a file:line so you can defend it live. The golden
rule: **never let one layer's protection stand in for another's.** The fastest
way to lose a security thread is to answer "command injection" with the exec
hardening when the asker actually meant "same-user rogue process" — two
different threats, two different answers.

---

## The two threats people conflate

| Objection | What it really is | Answer |
|---|---|---|
| "This is command injection." | Can a malicious template/param turn the broker into **arbitrary code execution**? | **No — prevented.** Fixed allowlisted binary, no shell, `--` guard, scrubbed env, trust gate. |
| "A rogue codex process can vend credentials through the broker." | Can a **same-user process** make a well-formed broker call it wasn't meant to? | **Partly open by design.** Identity is a same-user bearer signal; the vend is policy-gated + audited (drift protection), fully closed only by the tier-3 sandbox. |

Keep these apart in every reply.

---

## Q: "Isn't the broker a command-injection vector?"

**No — and this is specifically hardened.** A malicious template or a poisoned
parameter cannot make the broker execute an arbitrary command:

- **No shell.** Execution is `exec.CommandContext(bin, args...)`
  (`daemon/internal/resolve/resolve.go:94`).
- **The binary is fixed and allowlisted**, never template-chosen — it's the
  backend's `defaultBin` (`daemon/internal/resolve/resolve.go:45`).
- **Params are literal argv after a `--` guard.** e.g. `op read --no-newline --
  <ref>` — a poisoned ref is one argument, not a flag or command
  (`daemon/internal/resolve/backend_onepassword.go:31`).
- **Scrubbed environment.** The subprocess gets the backend's allowlist only —
  never the daemon env, other secrets, or `AKASHA_*`
  (`daemon/internal/resolve/resolve.go:95,159`).
- **Source-backed brokers are trust-gated.** The daemon refuses to run the
  backend at all unless the template is trusted
  (`daemon/internal/server/server.go:925-927`).

The *most* a caller can make the broker do is its legitimate job: run the one
allowlisted backend on a charset-validated reference. There is no field in
which to place a command.

**Paste-ready:**

```
No — command injection is specifically prevented. The backend runs via
exec.CommandContext with no shell; the binary is a fixed allowlisted name
(not template-chosen); the template's reference is one literal argv element
after a "--" guard, so it can't inject a flag or a command; and the subprocess
env is a scrubbed allowlist (no daemon env, no other secrets, no AKASHA_*). A
source-backed backend also won't run at all unless the template is trusted.
The most a caller gets is the broker doing its legitimate job — e.g. `op read`
on a charset-validated ref. There's no field to put a command in.
```

---

## Q: "A rogue codex process can just vend credentials through the broker, right?"

**Under the default policy, yes — and we document it rather than hide it.** This
is a *same-user identity* gap, not command injection:

- Agent identity is a **bearer signal from the environment**, not OS
  attestation. `resolveAgentID` takes the verified key if one is presented, else
  the self-reported value (`daemon/internal/server/server.go:164`); there's no
  `SO_PEERCRED`/UID gate beyond same-user. So the daemon can't cryptographically
  distinguish the real agent from another same-user process claiming its id.

**But the vend is not unconditional.** Every broker call flows through `credsFor`:

- It's evaluated by the **policy gate** as `Action: assume, Risk: critical`, and
  **both allow and deny are audited** with agent id + tool
  (`daemon/internal/server/server.go:897-915`).
- Under the **default seamless policy** brokered `assume` is *allowed* — so a
  rogue vend succeeds but is logged. Set policy to `ask`/`deny` on `assume`
  (per-agent or per-provider) and the rogue vend is **blocked, or gated behind a
  fail-closed human dialog**.

So the honest tiering:

1. **Today (config tier):** drift protection + detection. A rogue same-user
   process *can* vend under default policy; tighten policy to gate it; every
   attempt is audited (loud).
2. **Possession tier:** a secret moved fully into the vault (`akasha protect`,
   or agent-stored) has **no plaintext copy** — the only path to the value is
   the audited socket, so bypassing interception gains nothing.
3. **Sandbox tier (`akasha run`, planned):** the agent runs where the
   vault/keychain/plaintext are unreachable and the socket is the only exit, and
   **the sandbox is the identity** — this is where the rogue-vend gap closes
   hard.

**Paste-ready:**

```
Right, and I won't pretend otherwise: identity is a same-user bearer signal,
not OS attestation, so a rogue same-user process CAN make a well-formed broker
call under the default policy. That's a different thing from command injection
(which is prevented). What the broker vend is NOT is unconditional — it goes
through the policy gate as a critical-risk "assume", and allow *and* deny are
audited. The default policy is seamless (allows it, logs it); set it to
ask/deny and the rogue vend is blocked or gated behind a fail-closed human
dialog. The gap is fully closed only by the planned sandboxed launch, where the
sandbox itself is the identity. It's all in the threat model's enforcement
ladder — I'd rather you read the tier honesty there than have me oversell the
config tier.
```

---

## Q: "The agent brokered aws — what stops `aws s3 rm --recursive`?"

Nothing at the command layer — **Akasha is not a command firewall, and we don't
claim to be.** The credential is no broader than what you vaulted; every
operation is an audited per-op callback (agent + task); and policy can `deny`/
`ask` at the assume boundary for a given agent/provider/risk. Command-level
least privilege is scoped/short-lived creds (planned `mint`), not argv
inspection.

---

## Q: "Why trust a tool that scans my machine for AWS/SSH keys?"

Because you don't have to trust it — you can read it. Open source (Apache 2.0);
local-only in alpha (no cloud to exfiltrate to); the key lives in the OS
keychain, never on disk; fully reversible (`discover` vaults copies, `restore`
and `uninstall` put originals back byte-for-byte); and the threat model
documents what it *doesn't* defend, including every known alpha limitation.

---

## Handy links to keep in the tab

- Enforcement ladder (the tier honesty): `docs/THREATMODEL.md#enforcement-ladder-honest-positioning`
- Trust boundary table: `docs/THREATMODEL.md#the-trust-boundary`
- Known alpha limitations (bearer identity, trust store): `docs/THREATMODEL.md#known-limitations-alpha--being-hardened`
- Command-injection defense: `docs/THREATMODEL.md` → "No command injection via ownership"
