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

## Linux prerequisites

Skip this on macOS. On Linux, do it **before** step 2 — the ordering is the part
that bites.

Akasha keeps your vault key in the OS credential store, never on disk. On Linux
that is the freedesktop Secret Service (`org.freedesktop.secrets`), provided by
**gnome-keyring** and reached over the **D-Bus session
bus**. There is no fallback: without one, the daemon cannot open or create a
vault, and `akasha start` exits with the credential store's own error.

On a desktop you already have this — logging in starts the keyring and PAM
unlocks your login collection. On a **headless server, container, devcontainer,
WSL or CI runner** you do not:

```bash
sudo apt install gnome-keyring dbus-x11 bubblewrap              # Debian / Ubuntu
sudo dnf install gnome-keyring dbus-x11 dbus-daemon bubblewrap  # Fedora
sudo apk add     gnome-keyring dbus-x11 bubblewrap              # Alpine
```

**Two of those lines used to be wrong, and the failure looked like akasha's.**
Two separate things are needed: a Secret Service provider (gnome-keyring) and a
binary that can start a session bus. go-keyring shells out to `dbus-launch` *by
name*, and the package called `dbus` does not always carry it — on Fedora 41
`dnf install dbus` pulls dbus-broker and provides none of `dbus-launch`,
`dbus-run-session` or `dbus-daemon`, so the install succeeds and the next
command fails identically. On Alpine, `dbus` gives you `dbus-run-session` but
still not `dbus-launch`. `dbus-x11` is the package that carries it on all three.

On any other distro: install gnome-keyring, then whichever package provides
`dbus-launch`. Check with `command -v dbus-launch` before going further.

`bubblewrap` is there because `akasha run` needs it. Everything else works
without it; `akasha run` refuses to launch, and `akasha sandbox doctor` says so.

Verified end to end on Ubuntu 24.04, Debian 12, Fedora 41 and Alpine 3.20
(arm64, as a non-root user). Arch is not currently tested.

Then start a session bus that **outlives the command**, unlock the keyring, and
set up:

```bash
export DBUS_SESSION_BUS_ADDRESS="$(dbus-daemon --session --fork --print-address)"

stty -echo; printf "keyring password: "; read P; stty echo; echo
printf %s "$P" | gnome-keyring-daemon --unlock
akasha setup
```

**Not `dbus-run-session -- akasha setup`.** That form ends the bus the moment
setup exits, so setup succeeds and the very next akasha command reports a locked
vault and *"A new key was NOT generated"* — which reads like data loss and is
not. `dbus-run-session` is fine when everything you need runs *inside* it; it is
the wrong shape for a setup step you then follow with other commands.

### Unlock first — an unlock afterwards does not take

This is the one thing no error message can tell you. If `akasha start` runs
first, D-Bus *activates* gnome-keyring on demand, and it comes up with no
unlocked collection. Running the obvious fix at that point does **not** recover:

```
$ akasha start                     # fails: cannot unlock collection …/aliases/default
$ gnome-keyring-daemon --unlock    # exits 0, looks fine
$ akasha start                     # STILL fails: cannot unlock collection …/login
```

The already-running daemon tries to raise a graphical prompter, which is not
there. Kill it and start over:

```bash
pkill -f gnome-keyring-daemon

# The same persistent bus as above — the trailing `akasha start` needs it too.
export DBUS_SESSION_BUS_ADDRESS="$(dbus-daemon --session --fork --print-address)"

stty -echo; printf "keyring password: "; read P; stty echo; echo
printf %s "$P" | gnome-keyring-daemon --unlock
akasha start &
```

Note the `&`: `akasha start` runs in the foreground and does not daemonize
itself. Under systemd the unit handles that; started by hand, it holds the
terminal.

With the keyring unlocked first, everything works normally — vaulting, daemon
restarts and `akasha assume` — verified on Ubuntu 24.04, Debian 12, Fedora 41
and Alpine 3.20.

### If you use `ask` policy rules

Those need a dialog as well as a keyring: install `zenity`, and make sure the
systemd user unit can reach your display. See
[POLICY.md](POLICY.md#effects).

### What this protects, and what it does not

Once the login collection is unlocked, the Secret Service has **no per-caller
authorization** — any process on your session bus can request the item. Set a
vault passphrase and run agents under `akasha run` if that matters to you;
[THREATMODEL.md](THREATMODEL.md#known-limitations-alpha--being-hardened) has the
detail.

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
akasha run claude --assume github:default -- claude
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

### Which Secret Service providers actually work

Akasha needs a provider that serves `org.freedesktop.secrets` on the session
bus. **gnome-keyring does; it is what Akasha is tested against.**

KWallet and KeePassXC are often listed as Secret Service providers, and the
packages most distributions ship today are not:

- `kwalletd5` — the KF5 build in Ubuntu 24.04 — does not implement the name.
  `strings kwalletd5 | grep -c org.freedesktop.secrets` returns 0, no `.service`
  file advertises it, and `akasha start` against a running kwalletd5 fails with
  *"The name org.freedesktop.secrets was not provided by any .service files"*.
  The KF6 `kwalletd6` does implement it.
- KeePassXC implements it only when built with the Secret Service integration
  enabled AND with a display to unlock in; it aborts without one.

If you are on KDE, either install `gnome-keyring` alongside, or use `kwalletd6`.
