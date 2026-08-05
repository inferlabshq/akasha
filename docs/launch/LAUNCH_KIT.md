# Launch kit

Assets for the public launch. Companion doc: [OBJECTIONS.md](OBJECTIONS.md) —
code-cited answers for the hard questions (keep it open in a tab on launch day).

Fill `[threat model link]` and `[github link]` with real URLs before posting.

---

## 1. README trust section

Drop in high — right after the "Core trust guarantee" line, above the
`curl | sh`. Turns the #1 objection into the pitch.

```markdown
## "Why would I trust a tool that reads my AWS keys and SSH keys?"

Fair question — you should ask it of anything that scans your machine for
credentials. Here's the honest answer, and every claim is checkable:

- **It's open source (Apache 2.0).** The vault, the crypto, the credential
  path — all of it is in this repo. Read it, don't take our word for it.
- **Nothing leaves your machine.** Alpha is local-only — there is no cloud
  component to phone home to. The encryption key lives in your OS keychain,
  **never on disk**. The vault is XChaCha20-Poly1305; the key is wrapped with
  ML-KEM-768 (post-quantum).
- **Agents never hold the raw secret.** When an agent "assumes" a credential
  it gets a short-lived (1h TTL, `0600`, RAM-backed) file handle or a
  per-operation callback — not the value. `git` calls back through the daemon
  on every push; the token never enters the environment.
- **It's fully reversible.** `discover` vaults *copies* — your originals stay
  put. `akasha protect` moves a file into the vault and leaves a stub;
  `akasha restore` (and `akasha uninstall`, automatically) puts every byte
  back. Removing Akasha never breaks your machine.
- **We tell you what it *doesn't* protect.** The [Threat Model](docs/THREATMODEL.md)
  documents the trust boundary, an explicit enforcement ladder, and every known
  alpha limitation — including the ones we haven't hardened yet.

> **This is alpha.** Don't use it to protect secrets you can't rotate.
```

---

## 2. README FAQ — "what stops the agent stealing the value?"

Place next to the trust section. This is the short form; the long, code-cited
form lives in [OBJECTIONS.md](OBJECTIONS.md).

```markdown
### "If the agent can broker a secret, what stops it stealing the value?"

Depends on the tier, and we're explicit about which is which:

- **Not command injection.** A malicious template can't turn the broker into
  arbitrary code execution — fixed allowlisted binary, no shell, `--` guard,
  scrubbed env, trust gate. The most a caller gets is the broker's legitimate
  job on a charset-validated reference.
- **Not a command firewall.** Once an agent brokers a provider it can make any
  call that credential allows. Akasha scopes and audits every operation and
  lets policy deny/ask at the boundary — it does not inspect your commands.
- **Config-level brokering is drift protection + detection.** Identity is a
  same-user bearer signal, so a rogue same-user process can vend under the
  default policy — but the vend is audited, and policy can gate it to a
  fail-closed "ask". Not an adversarial barrier.
- **Possession is the hard guarantee.** A secret moved fully into the vault
  (`akasha protect`, or agent-stored) has no plaintext copy — the only path is
  the audited socket.
- **Sandboxed launch (`akasha run`, planned)** is the tier where exfiltration
  becomes impossible rather than merely audited: the sandbox is the identity.

Full detail: [enforcement ladder](docs/THREATMODEL.md#enforcement-ladder-honest-positioning).
```

---

## 3. Show HN post

**Title** (plain and specific beats clever):

```
Show HN: Akasha – a local vault that keeps AI agents from leaking your secrets
```

**Body:**

```
Hi HN — I built Akasha because AI coding agents now run with real
credentials on real machines, and the current answer is "paste your AWS keys
and GITHUB_TOKEN into an MCP config in plaintext and hope." That felt backwards
for a security-sensitive workflow.

Akasha is a local daemon (single Go binary, no runtime deps) that does two
things:

1. Detects and captures sensitive data flowing through agent tool calls,
   replacing real values with vault:// tokens, with a full audit trail of
   what every agent touched and why.

2. Brokers credentials to agents without ever handing over the raw secret.
   When Claude Code (or any MCP client) "assumes" an AWS profile or a git
   token, it gets a short-lived, RAM-backed file handle or a per-operation
   callback — not the value. git calls back through the daemon on each push;
   the token never lands in the environment. Every access is policy-gated
   and audited.

The vault is XChaCha20-Poly1305; the key is wrapped with ML-KEM-768 and lives
in your OS keychain, never on disk. Providers (AWS, GitHub, or your own
internal system) are data-only YAML plugins — there are no compiled-in
providers, and an untrusted plugin is inert until you sign or approve it.

It's Apache 2.0. Install is `curl -sSL https://getakasha.dev/install | sh`
then `akasha setup`, which scans for creds, vaults them, and writes the MCP
config in one shot.

Two things I want to be upfront about:

- It's alpha. Don't protect secrets you can't rotate.
- An agent runs as your user with a shell, so no config-level mechanism is
  bypass-proof against a determined adversary. I wrote a threat model that
  says exactly what each tier does and doesn't guarantee, plus every known
  limitation, rather than marketing it as airtight: [threat model link]

Repo: [github link]. Would genuinely like to hear where the trust model
breaks for you.
```

**First comment (post immediately, yourself — it's your reputation):**

```
A few design decisions I expect questions on, addressed up front:

"Why trust a thing that scans my machine for keys?" — it's open source, so
don't. The crypto and the credential path are all in the repo. It's local-only
in alpha (no cloud to exfiltrate to), the key never touches disk, and it's
fully reversible — discover vaults copies and leaves your originals; uninstall
restores every escrowed file byte-for-byte.

"Is the broker a command-injection vector?" — no, specifically hardened: no
shell, fixed allowlisted binary (not template-chosen), the reference is one
literal argv element after a "--" guard, scrubbed env. The most a caller gets
is the broker's legitimate job on a charset-validated ref.

"Can a rogue same-user process vend through the broker?" — under the default
policy, yes, and I won't pretend otherwise. Identity is a same-user bearer
signal, not OS attestation. The vend is audited and policy-gateable (set it to
ask/deny for a fail-closed dialog), but it's drift protection, not an
adversarial barrier — that closes fully at the planned sandboxed-launch tier,
where the sandbox is the identity. It's in the threat model's known
limitations; I'd rather name my own soft spots than have them named for me.

"What stops a malicious plugin?" — an unsigned/unapproved plugin can't run a
backend, own an agent's environment, or execute code. Trust is an Ed25519
signature from a publisher you added, or an explicit hash-bound approval;
editing the file breaks it.
```

---

## 4. Launch-day logistics

- **Gate 0 (before any post):** repo public · GitHub Release cut on the latest
  tag so `install.sh` resolves from GitHub, not just the CDN · demo GIF in the
  README · trust section + FAQ merged.
- **Timing:** Tue–Thu, ~8–10am ET. Block the whole day.
- **Order:** Show HN first (origin), then r/LocalLLaMA + r/selfhosted, then
  X/Bluesky, then MCP/Claude Code communities — staggered *after* HN gains
  traction, not simultaneously.
- **Presence:** answer every thread live. Keep [OBJECTIONS.md](OBJECTIONS.md)
  open. The threat model is your ammo — link it liberally.
