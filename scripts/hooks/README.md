# Agent session guardrails

`akasha-secret-guard.sh` is a [Claude Code](https://claude.com/claude-code)
`PreToolUse` hook that keeps an agent's shell commands from handling raw
credentials directly. It blocks three classes of command and, on each denial,
names the Akasha-native way to do the same thing:

| | Blocked | Instead |
|---|---|---|
| **A** | un-brokered `git` network operations | `akasha exec --assume <provider>:<profile> -- git …` |
| **B** | reading credential files Akasha manages (`~/.aws/credentials`, `~/.ssh/id_*`, `vault.db`, key backups, `.netrc`, `.pem`, `.p12`) | `akasha exec` / `akasha assume`, or `akasha inspect` for metadata |
| **C** | printing the agent key or OS keychain secrets | route through the broker |

It is **a guardrail, not a sandbox**. It pattern-matches the command string and
can be bypassed by obfuscation; it exists to stop *accidental* raw-secret
handling. For actual containment, launch the agent with `akasha run`, which
applies an OS sandbox — see [`docs/THREATMODEL.md`](../../docs/THREATMODEL.md).

## Install

```bash
mkdir -p ~/.claude/hooks
cp scripts/hooks/akasha-secret-guard.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/akasha-secret-guard.sh
```

Then register it in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/akasha-secret-guard.sh",
            "statusMessage": "Akasha secret-guard"
          }
        ]
      }
    ]
  }
}
```

## Test

```bash
bash scripts/hooks/akasha-secret-guard.test.sh
```

Run it after **any** change to the guard. The suite is split deliberately:

- **MUST STILL BLOCK** — every dangerous command, so a fix for a false positive
  cannot quietly open a hole.
- **MUST NOW BE ALLOWED** — the false positives, including ones specific to this
  project: `akasha put env:stripe …` uses the generic `env:` provider prefix, and
  Go source that names the agent-key variable (`t.Setenv(…)`, `os.Getenv(…)`) is
  ordinary code, not an attempt to print a secret.

## Known false positives

Section B matches credential-file *names* as substrings, so a command that
merely mentions one — grepping for the string, or looping over a vault label
that happens to end in `.pem` — is denied even though it reads nothing. That is
inherent to substring matching on filenames, and B is the highest-value rule, so
it is left strict on purpose: a false denial costs a rephrased command, a false
allow costs a credential.
