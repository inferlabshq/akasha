#!/usr/bin/env bash
# Akasha secret-guard — PreToolUse hook for Bash.
#
# Purpose: force all key/secret handling through Akasha. Deterministically blocks
# Bash commands that would (A) run un-brokered git network ops, (B) read raw
# credential files Akasha manages, or (C) print the agent key / OS keychain
# secrets. On a block it returns a deny decision plus the Akasha-native way to do
# the same thing. This is a guardrail, not a sandbox — it pattern-matches the
# command string and can be bypassed by obfuscation; it exists to stop accidental
# raw-secret handling, not a determined adversary.
set -euo pipefail

input="$(cat)"
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // ""')"
lc="$(printf '%s' "$cmd" | tr '[:upper:]' '[:lower:]')"

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# --- A) Un-brokered git network operations -------------------------------------
if printf '%s' "$lc" | grep -Eq '(^|[^a-z-])git([^a-z-].*)?(clone|fetch|push|pull|ls-remote|remote +update)'; then
  if ! printf '%s' "$lc" | grep -Eq 'akasha +exec'; then
    deny "Akasha guard: git network operations must be brokered by Akasha so the token is resolved per-operation and never enters the environment. Re-run wrapped, e.g.:  akasha exec --assume github:inferlabs -- <your git command>   (run 'akasha list' for other profiles)."
  fi
fi

# --- B) Reading/printing raw credential material -------------------------------
if printf '%s' "$cmd" | grep -Eq '\.aws/credentials|\.aws/config|/\.ssh/id_[A-Za-z0-9_]+|\.akasha/vault\.db|akasha-key\.backup|\.akb([^A-Za-z0-9]|$)|\.netrc|\.pem([^A-Za-z0-9]|$)|\.p12([^A-Za-z0-9]|$)'; then
  # Public keys are not secret — allow those through.
  if ! printf '%s' "$cmd" | grep -Eq '\.pub([^A-Za-z0-9]|$)'; then
    deny "Akasha guard: direct access to raw credential files is disabled — Akasha manages these. To USE a credential:  akasha exec --assume <provider>:<profile> -- <cmd>   or   akasha assume <provider>:<profile>. To inspect metadata WITHOUT decrypting:  akasha inspect  (or the vault_inspect MCP tool)."
  fi
fi

# --- C) Dumping the agent key or OS keychain secrets ---------------------------
#
# The printing verbs must appear in COMMAND POSITION — start of line or after a
# separator, and followed by whitespace. Matching them as bare substrings caught
# ordinary source code: Go's `t.Setenv("AKASHA_AGENT_KEY", key)` contains "env"
# followed later by the variable name, so writing a *test* for key handling was
# denied as if it were printing a secret. A guardrail that blocks writing the
# code is one people switch off.
print_verb='(^|[;&(]|&&|\|\||[[:space:]])(echo|printf|printenv)[[:space:]]'

# `env` is handled separately: bare `env` (or piped into anything) dumps the
# whole environment including the key, while `env VAR=x cmd` is the ordinary way
# to run a command with an override and must stay allowed.
bare_env='(^|[;&(]|&&|\|\||[[:space:]])env[[:space:]]*(\||;|&|$)'

if printf '%s' "$lc" | grep -Eq "${print_verb}[^|;&]*akasha_agent_key" \
   || printf '%s' "$lc" | grep -Eq "$bare_env" \
   || printf '%s' "$cmd" | grep -Eq '\$\{?AKASHA_AGENT_KEY' \
   || printf '%s' "$lc" | grep -Eq 'security +find-(generic|internet)-password[^|]* -w'; then
  deny "Akasha guard: printing raw secrets, the Akasha agent key, or OS keychain entries is disabled. Route the operation through Akasha's broker (akasha exec/assume) instead of extracting the raw value."
fi

# Default: allow.
exit 0
