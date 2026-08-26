# Changelog

All notable changes to Akasha are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Docs

- **The threat model no longer implies the keychain ACL is cross-platform.** It
  stated the vault key was protected by "the OS keychain ACL (only the
  code-signed daemon can use it)" without qualification. That is a macOS
  property: Linux stores the key via the D-Bus Secret Service, which has no
  per-caller authorization at all — once the login collection is unlocked, any
  process on the session bus can request the item. Known limitations now carry a
  bullet spelling out the asymmetry, what narrows it (a vault passphrase is the
  only real second factor on Linux), and the fact that `akasha run`'s bubblewrap
  profile does not yet close the D-Bus channel the way the macOS profile closes
  securityd.
- **…and the macOS half of that bullet was wrong too.** It said a keychain
  item's ACL binds to the requesting binary's code signature, so only the signed
  `akasha` daemon can use the vault key. Akasha never gets that property:
  `go-keyring`'s darwin backend shells out to `/usr/bin/security` instead of
  calling the Keychain API in-process, so the ACL is written for *that* binary
  and akasha's own signature never enters the check. Four differently-signed
  akasha binaries — stable identity, ad-hoc, a fresh cross-build, and one signed
  `com.example.totally-different` — all read the key from a real vault with no
  prompt. Every place that repeated the claim now says what is true: the threat
  model, `docs/macos-signing.md` and its index entry in `docs/README.md`, the
  README, `install.sh`, `.github/workflows/release.yml` (where it was the stated
  reason for signing at all, and the text of a CI warning), and
  `docs/design/same-user-identity.md`, where it had been cited as the in-tree
  precedent justifying peer code-signature attestation — a roadmap rung resting
  on a retracted premise. On **both** platforms the vault key is guarded by the
  user account, and a same-user process can read it. Code signing is retained
  and still required — launchd refuses to run an unsigned binary and Apple
  Silicon kills one outright — it just is not a confidentiality control. (The
  alpha.1 entry below still carries the original wording; it is left as the
  record of what was claimed at the time.)
- **Linux's actual prerequisite is now documented where a user meets it.**
  Nothing in the README, `docs/getting-started.md` or the installer said that
  Linux needs an installed, unlocked freedesktop Secret Service, even though
  vaulting cannot work without one. All three now do, including the ordering
  rule that no error message can teach: unlock the keyring *before* akasha first
  touches the bus, because a collection akasha has already woken up locked will
  not unlock in place — you have to `pkill -f gnome-keyring-daemon` and start
  over. The installer's closing block still leads with a bare `akasha setup` on
  Linux and marks the rest "first run only": a desktop login unlocks the keyring
  for you, and folding the command into a `dbus-run-session` one-liner made
  every Linux user read a wall of headless-box instructions to find the one line
  they needed.

### Security

- **An agent could read any file you had escrowed with `akasha protect`, in one
  request, under the shipped default policy.** `/credential/retrieve` is gated
  as `assume`, and `assume` is deliberately permissive so routine git/AWS work
  is not interrupted. For a discovered credential that is fine — the endpoint
  hands back `vault://` tokens. For an `escrow:` entry the value **is** the
  secret: the verbatim bytes of the file you took off disk. So
  `GET /credential/retrieve?name=escrow:/home/you/.aws/credentials` with any
  `agt_` key returned the whole credentials file, over the unix socket and over
  loopback alike, with `GET /label/list?prefix=escrow:` available first to
  enumerate the targets. The same agent's `POST /retrieve` was correctly
  refused, which is what made this an authorization gap rather than a design
  choice: protect's central claim — "agents can no longer read it" — was false
  for exactly the caller it was written about. The `escrow:` namespace is now
  the **human's**: the daemon refuses to read, list, bind or unbind one for any
  caller that is not the local CLI, in code, before policy is consulted. The
  guard keys on the entry's category, so binding a fresh alias to an escrow
  token does not walk around it. The owner is unaffected — `protect`, `restore`
  and `uninstall` all still work — which the fix that suggests itself does not
  manage: shipping the `{action: assume, provider: escrow}` rule this project's
  own POLICY.md documented locks a headless user out of their own file, since
  `ask` fails closed with no dialog to answer. That recommendation has been
  removed from POLICY.md.
- **`akasha label rm --yes escrow:<path>` destroyed the escrowed original.** It
  printed `✓ removed` and left the file on disk as a stub with nothing able to
  reach the bytes — while the warning it printed said to recover by re-running
  `akasha discover` "if the source still exists". The source *is* the stub. The
  daemon now refuses to remove an `escrow:` label while the original is not back
  on disk, and names the reversal (`akasha restore <path>`, after which removing
  the label loses nothing). The stranding case — the file's directory is gone,
  so restore cannot put it back — has a named acknowledgement,
  `--destroy-escrowed-original`, which is audited as data loss rather than as a
  routine unbind.
- **`akasha put escrow:<path> --stdin` destroyed it the same way, and reported
  success.** An escrow label is the only handle on the file it names, so
  re-pointing one strands that file exactly as removing it does — but the guard
  had been attached to `/label/delete` rather than to the binding, so it fenced
  one of two doors. The rebind printed `✓ stored`, after which `akasha restore`
  failed with an envelope path mismatch and `akasha uninstall --purge` could not
  put the file back either. Re-pointing an `escrow:` name is now refused for
  **every** caller while the original is not on disk, with the same reversal and
  the same named override; `akasha protect` re-escrowing the same file — the one
  rebind that strands nothing — still works.
- **The "is it safe to remove?" test was decided by whoever could write the
  file.** It asked whether the file on disk was a *stub*, so any other bytes at
  that path — one space would do, and an agent that the escrow gate keeps away
  from every escrow endpoint can still write there — made the daemon answer
  "restored, safe to remove" and take the original with it. The question is now
  answered against the escrowed bytes themselves, and fails closed on anything
  it cannot compare. `akasha label rm`'s "`<path>` is back on disk, so this only
  forgets the escrow entry" is a claim the daemon has checked rather than one
  the CLI guessed.
- **A failed escrow lookup advised the command that destroys escrowed files.**
  The "nothing is vaulted for provider %q" hint rendered for the escrow provider
  as ``run `akasha discover escrow` or `akasha put escrow:<name>` `` — pointing a
  user who had just failed to find a protected file at the one command that
  orphans it. Escrow misses now name `akasha protect` instead.
- **`akasha restore` reversed a protection with no confirmation.** The stub left
  on disk names the command that undoes it, in a comment meant for the human,
  and an agent that read the stub ran it. Restore now confirms like `protect`
  does (`--yes` to skip, fail closed with no terminal) on top of the daemon-side
  refusal above.
- **`akasha protect` reported success for a hardlinked file whose plaintext was
  still readable.** Protect replaces a *name*: the stub is renamed over the
  path, which does nothing to a second hardlink still resolving to the untouched
  inode. It now refuses when `st_nlink > 1`, naming the sibling link when it is
  in the same directory, and takes `--allow-hardlinked` from a user who knows.
- **`akasha run` left the Linux credential store reachable from inside the
  sandbox.** `DenyKeychain` masked `~/.local/share/keyrings` and
  `~/.local/share/kwalletd` — the keyring *databases* — and stopped there. But
  the vault never reads those files: it calls `org.freedesktop.secrets` over the
  **D-Bus session bus**, served by gnome-keyring/kwalletd/KeePassXC, processes
  living outside the sandbox with the unlocked collection in their own memory.
  Under `--dev-bind / /` that socket passed straight through, so a supervised
  agent could ask for the ML-KEM vault key by exactly the route the daemon uses,
  on a profile that reported success. macOS was never affected — it denies the
  `securityd` mach services, and a keychain item is unreachable any other way.

  The bus socket is now masked too: the path from `DBUS_SESSION_BUS_ADDRESS`
  (percent-decoding handled, multiple addresses handled), plus the
  `$XDG_RUNTIME_DIR/bus` and `/run/user/<uid>/bus` fallbacks a client uses when
  the variable is unset, plus gnome-keyring's own control socket directory.
  Because these paths come from the *environment* rather than from a Spec, they
  are held to the same `Validate` rule as every other mount argument — the check
  was factored out of `Spec.Validate` so there is one rule, not two.

  Two honest limits, both documented in `docs/THREATMODEL.md`:

  - bwrap can mask a socket but cannot filter methods on it, so a supervised
    agent now loses *every* session-bus service (portals, notifications,
    `libsecret` git credential helpers). That last one is the point; the others
    are collateral. Narrowing this to one bus name needs `xdg-dbus-proxy`.
  - A bus advertised as `unix:abstract=` has no filesystem object to mask. It is
    skipped deliberately rather than guessed at — and the sandbox self-test,
    which performs the vault's *real* `keyring.Get` from inside the profile,
    turns that case into a refused launch instead of a silent hole. The
    self-test failure now explains this on Linux rather than just reporting
    "still reachable".

### Fixed

- **`install.sh` reported success while installing zero provider templates.**
  `tar -xzf` ran unchecked, the copies that followed were `2>/dev/null || true`,
  and the green tick after them was unconditional — so a missing `tar` (some
  minimal images ship none), a truncated download, an archive with the wrong
  layout or an unwritable directory all printed `✓ Installed provider templates`
  and exited 0. What the user got was a vaulting product that vaults nothing,
  discovered much later as `No templates loaded.` and `No credentials found.`,
  with nothing pointing back at the install. Every step is now checked, and
  success is asserted by counting what actually landed in the destination rather
  than by trusting the commands that wrote there; the tick names the count. A
  release that serves a binary but no `akasha-templates.tar.gz` is fatal too —
  it used to warn and exit 0, which is an honest sentence with the same ending,
  and `release.yml` packages that bundle on every tag, so its absence is a
  broken release rather than one that opted out. `scripts/install.test.sh`
  drives the whole installer against a local `file://` release and holds the
  line on every one of those failure modes plus the source-build path, and CI
  now runs it (and the secret-guard hook suite) on every PR instead of only the
  Go suites.
- **A Linux daemon that could not reach a keyring said only `exec: "dbus-launch":
  executable file not found in $PATH`.** That is the first thing a new Linux user
  sees, and it names neither the requirement nor a fix. Both the key-setup write
  and the guard that refuses to create a vault over an unreadable store now
  explain what akasha needs, how to install it, and the unlock-first ordering —
  including the `pkill` that is the only way out once a locked keyring has been
  activated. `akasha vault restore` and `akasha vault backup` carry the same
  text, which matters most for `restore`: the locked-vault error ends by telling
  you to run it, and on the machine that produced that error the credential
  store is exactly what is broken — so the recovery path akasha's own message
  routes you down used to end at `restore keychain: exec: "dbus-launch":
  executable file not found in $PATH`.
- **`akasha setup --yes` left a half-configured machine on a box with no
  keyring.** It registered the login service first and opened the vault
  afterwards, so it wrote (and under systemd enabled) a `Restart=always` unit
  and *then* died on the credential store, exit 1. The credential store is the
  one prerequisite setup cannot supply for you, so it is now the first thing
  checked and nothing is written when it fails.
- **Every runtime error arrived buried under cobra's flag table.** "daemon not
  reachable", "vault is locked" and its multi-line recovery instructions were
  each followed by ~12 lines of flag help, which pushes the message that matters
  off a short terminal and makes an environment problem read as a CLI mistake. A
  dozen commands had been silenced one at a time and about twenty had not,
  including `start`. Suppression now happens once, in the root command's
  `PersistentPreRun` — which cobra runs *after* flag and argument validation —
  so a mistyped flag or a wrong argument count still gets the usage text, and
  only errors a command raises itself are silenced. The twelve per-command
  declarations it replaced are gone rather than left as harmless duplicates:
  a struct-level `SilenceUsage` is set before cobra parses anything, so those
  commands went on swallowing usage for syntax errors too — `akasha put
  --no-such-flag` answered with a bare `unknown flag` and no list to correct it
  against, while `akasha list --no-such-flag` printed one.
- **The installer's PATH hint always named `~/.zshrc`.** Right on macOS, wrong
  on every Linux distro, where the default shell is bash: the line landed in a
  file nothing sourced, so the very next instruction (`akasha setup`) was
  command-not-found. It now names the file the user's actual shell reads, and
  falls back to `~/.profile` when `SHELL` is unset (containers, CI). The
  "…or run this right now" line that follows is per-shell for the same reason:
  fish is not POSIX, so a shared `export PATH="…:$PATH"` handed fish users a
  syntax error directly under a correct `fish_add_path` suggestion. The hint
  also prints on stdout with the rest of the next-steps block, because splitting
  it across stdout and stderr let the two interleave whenever both landed in one
  pipe.
- **Discovery gave you the wrong credential, silently.** Two findings that named
  the same `provider:instance` were both vaulted, and the second overwrote the
  first — one label points at one token — while the listing printed `✓ vaulted`
  for each. On the pairing our own fixtures model (a shared credentials file
  plus a stale `export AWS_ACCESS_KEY_ID` in `~/.zshrc`) `aws:default` resolved
  to the shell rc, exactly inverting the order every template documents: "MOST
  AUTHORITATIVE FIRST". `dedupe` did honour that order, but only for
  byte-identical findings, and a rotated key is precisely the case where they
  differ. The engine now resolves the collision where it happens: the first
  declared source wins, and the losers are reported on the winner so the review
  step can name the file it did NOT take. Nothing on screen could have revealed
  this before — competing rows render identically, because the listing prints
  field names and never values.
- **`akasha setup` vaulted everything without asking, and so did any piped
  `akasha discover`.** `echo n | akasha discover all` vaulted 32 credentials;
  "no" was one of the inputs that did it. The trigger is not the pipe, it is any
  stdin that is not a terminal — CI, a Makefile, `curl | sh`, `docker run`
  without `-t`, and an agent running `akasha`, which is the stated audience.
  Setup was worse: it had no listing, no prompt and no `--dry-run` at all, so
  the honest warning in `discover` described the path a new user is least likely
  to take first. Both now show the same review listing, and neither writes to
  the vault without a terminal unless `--yes` says so. `discover` exits non-zero
  when it declines, because a green exit over an unchanged vault is how a
  provisioning script comes to believe it is done.
- **Quoted credentials were vaulted with their quotes.** `aws_access_key_id =
  "AKIA…"` was stored verbatim, and everything after the closing quote — a
  trailing `# comment` included — was kept as part of the secret. Storing it
  verbatim matched what botocore does, but Akasha does not hand the file to the
  SDK: it hands over a value out of a vault the user cannot inspect, so the
  quotes resurfaced days later as a signature error from a remote API naming
  nothing to go and look at. A value between matching quotes is now unquoted; an
  unquoted one stays verbatim, `#` and all, since only a quoted value has an
  unambiguous end.
- **`export AWS_ACCESS_KEY_ID = "AKIA…"` yielded half a credential.** The
  `env-lines` pattern allowed no space around `=` and no whitespace or quote in
  the value, so that line matched nothing — and because the neighbouring secret
  was written in a form it did accept, the result was not "no credential" but a
  half one: vaulted, labelled, reported `✓ vaulted`, and unusable at the moment
  it finally reached an SDK. Assignments are now read the way a shell reads
  them, and variable names match case-insensitively like the ini parser's keys
  always have — the two disagreed about what counted as a credential. Reading
  values the way a shell does also means recognising what is not one: a line
  that fetches its secret from elsewhere (`=$(pass show aws/key)`, `${VAR}`, a
  backticked command) names no credential, and is no longer captured as the
  literal text of the command. A `$` in the middle of a value is left alone —
  it is an ordinary character in a great many passwords.
- **`.env.example` was discovered and vaulted as a real credential.** A file
  that exists in order to be copied — `AWS_ACCESS_KEY_ID=your-key-here`, checked
  in beside the real `.env` — was swept up by `~/.env*` and became `aws:default`
  like anything else. Harmless while the last writer won; not harmless now that
  the first declared source does, since a sample file sitting ahead of a real
  one in the sweep would take the label. Glob sweeps now skip `.example`,
  `.sample`, `.template` and `.dist`. A rule that names such a file outright
  still reads it.
- **A host's letter case made a second instance for one token.**
  `https://u:t@GitHub.COM` in `~/.git-credentials` produced `git:GitHub.COM`
  alongside `git:github.com`. Hostnames are case-insensitive; the instance is
  now lower-cased before it becomes the label a credential helper is scoped by.

### Added

- **Policy `ask` now prompts on Linux.** `ask` was documented as fail-closed
  everywhere but only had a channel on macOS, so on Linux it behaved as a
  permanent `deny` — a rule the user wrote as "pause and ask me" silently became
  "never". Linux now gets a `zenity` dialog with the same wording, the same
  Deny/Allow buttons and the same default Deny as the macOS one; the dialog body
  is built once and shared, so its wording cannot drift per platform.

  `kdialog` is deliberately not a fallback. It has no default-no option, and it
  returns exit 1 for both "No" and "dismissed with Escape", so the label swap
  that would restore a default-deny button also turns an Escape into an Allow.
  A backend that fails open on Escape is worse than no backend.

  Two related hardening details: zenity renders `--text` as Pango markup, so
  caller-supplied values have `<` and `>` stripped (`--no-markup` is passed too,
  but the strip is what holds if a build ignores it) — the Linux equivalent of
  the AppleScript line-break forgery `dialogSafe` already closes. And zenity is
  resolved from a fixed absolute-path list, never `PATH`: the program that
  decides whether a gated operation proceeds must not be chosen by a directory
  any local process can write.

- **A denial now says when nobody could be asked.** An approver that exists but
  cannot reach a human — headless session, no dialog program — reported the
  same "approval not granted" as a human clicking Deny. It now names the cause
  and the fix (`no graphical session …`, `zenity is not installed …`).

## [0.1.0-alpha.3] - 2026-08-13

_Corrected after the fact: the entries below were written before this tag was
cut but were left under Unreleased, so the released notes under-described what
0.1.0-alpha.3 actually contained — including the authentication change, which is
the most important thing in it._

### Security

- **Authentication reduced privilege, so `agent revoke` was not enforcement.**
  The daemon inferred the trusted local human from the *absence* of an agent
  key: a request with no `X-Akasha-Key` was not a "verified agent", and the two
  most privileged paths — raw secret delivery through `/assume`, and starting an
  `akasha run` — were gated on exactly that negation. The keyless path was
  therefore not merely as privileged as a valid key, it was **more** privileged,
  and an agent whose key had just been revoked recovered everything (and gained
  more than its key ever carried) by dropping the header:

  ```
  $ AKASHA_AGENT_KEY=<revoked> akasha whoami aws:pk-website
  denied: agent key has been revoked
  $ unset AKASHA_AGENT_KEY && akasha whoami aws:pk-website
  <identity for every AWS credential in the vault>
  ```

  Privilege is now monotonic in authentication — presenting less can only get
  you less:

  - Every caller authenticates. A request with no key is refused with 401 on
    every endpoint except `/health`.
  - The local CLI has a real identity. The daemon mints a key for the reserved
    identity `cli` at startup and writes it 0600 as `cli.key` beside the vault.
    The human path is granted on an affirmative identity rather than an absence.
  - `agent create cli` and `agent create run:*` are refused, so a caller cannot
    mint itself a name that carries daemon authority. Enforced in the vault
    layer, because `agent create` opens the vault directly.
  - The CLI refuses to fall back to `cli.key` in a session that still advertises
    `AKASHA_AGENT_ID`, rather than quietly upgrading an agent to the human.
  - `akasha status` no longer suggests `unset AKASHA_AGENT_KEY` as a remedy —
    that advice was the bypass.

  **This does not lift the same-UID ceiling.** `cli.key` is readable by the
  user's own uid, so a local process that reads it can still act as the human.
  What changed is that doing so now requires stealing a specific, revocable,
  auditable credential instead of being rewarded for sending one fewer header.
  See `docs/design/same-user-identity.md`.

- A vault that cannot be read is no longer reported as an authentication
  failure. With every request authenticated, a storage fault would otherwise
  turn the whole daemon into "your key is wrong" and send users re-minting
  perfectly good keys to chase it. Non-sentinel verification errors return 500.


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

- **Grant redemption and audit attribution come from the key, not the body.** A
  caller can no longer be served under an `agent_id` it typed into a request:
  unauthenticated requests are refused, and a verified identity always overrides
  the body. Rules written against the daemon-assigned names (`akasha-list`,
  `akasha-helper`, `akasha-assume`, …) are unaffected — those still identify the
  local human, while an agent's verified identity replaces them.
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
