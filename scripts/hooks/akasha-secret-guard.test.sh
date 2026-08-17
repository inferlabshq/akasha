#!/usr/bin/env bash
# Tests for akasha-secret-guard.sh — drives the hook with a command string and
# checks allow/deny.
#
# Run after ANY edit to the guard. Loosening a pattern without re-running this
# is how a guardrail quietly stops guarding; the "MUST STILL BLOCK" list exists
# so a fix for a false positive cannot silently open a hole.
#
#   bash scripts/hooks/akasha-secret-guard.test.sh              # the repo copy
#   HOOK=~/.claude/hooks/akasha-secret-guard.sh bash …          # the installed copy
#
# Note: the cases live in this file rather than inline in a shell, because the
# dangerous strings would otherwise trip the very hook under test.
HOOK="${HOOK:-$(cd "$(dirname "$0")" && pwd)/akasha-secret-guard.sh}"

verdict() {
  # jq pretty-prints, so match the value with optional whitespace rather than
  # assuming a compact object.
  out=$(printf '%s' "$1" | jq -Rs '{tool_input:{command:.}}' | bash "$HOOK")
  if printf '%s' "$out" | grep -Eq '"permissionDecision":[[:space:]]*"deny"'; then echo DENY; else echo ALLOW; fi
}

fails=0
check() { # check <expected> <label> <command>
  got=$(verdict "$3")
  if [ "$got" = "$1" ]; then
    printf '  ok   %-6s %s\n' "$got" "$2"
  else
    printf '  FAIL want=%s got=%s  %s\n' "$1" "$got" "$2"
    fails=$((fails+1))
  fi
}

echo "MUST STILL BLOCK (regressions here are security holes):"
check DENY "echo \$KEY"            'echo $AKASHA_AGENT_KEY'
check DENY "echo \${KEY}"          'echo "${AKASHA_AGENT_KEY}"'
check DENY "printenv KEY"          'printenv AKASHA_AGENT_KEY'
check DENY "printf KEY"            'printf "%s" $AKASHA_AGENT_KEY'
check DENY "bare env"              'env'
check DENY "env | grep"            'env | grep AKASHA'
check DENY "env at end of chain"   'cd /tmp && env'
check DENY "keychain -w"           'security find-generic-password -s akasha-daemon -w'
check DENY "read aws creds"        'cat ~/.aws/credentials'
check DENY "read ssh key"          'cat ~/.ssh/id_ed25519'
check DENY "read vault db"         'cp ~/.akasha/vault.db /tmp/x'
check DENY "unbrokered git push"   'git push origin main'

echo
echo "MUST NOW BE ALLOWED (these were false positives):"
check ALLOW "Go t.Setenv literal"  't.Setenv("AKASHA_AGENT_KEY", key)'
check ALLOW "write Go test file"   'cat > x_test.go <<EOF
t.Setenv("AKASHA_AGENT_KEY", key)
EOF'
check ALLOW "os.Getenv in source"  'grep -n "os.Getenv(\"AKASHA_AGENT_KEY\")" main.go'
check ALLOW "env VAR=x cmd"        'env AKASHA_TEMPLATES_PATH=/tmp/t akasha start --socket ./s.sock'
check ALLOW "env assignment chain" 'env FOO=1 BAR=2 ./run.sh && echo done'
check ALLOW "unset the var"        'unset AKASHA_AGENT_KEY'
check ALLOW "brokered git"         'akasha exec --assume github:inferlabs -- git push'
check ALLOW "ordinary echo"        'echo "hello world"'
check ALLOW "grep source for env"  'grep -rn "getenv" internal/'
# `env:` is a real provider prefix in akasha's own docs — the generic env
# provider — so it must not look like a request to dump the environment.
check ALLOW "env: provider put"    'akasha put env:stripe STRIPE_API_KEY'
check ALLOW "env: provider exec"   'akasha exec --assume env:stripe -- ./charge.sh'
check ALLOW "env: provider assume" 'akasha assume env:datadog'
check ALLOW "env-lines in yaml"    'grep -n "source: env-lines" templates/aws.yaml'
check ALLOW "environment word"     'echo "reads the environment"'

echo
[ "$fails" -eq 0 ] && echo "ALL PASS" || echo "$fails FAILURE(S)"
exit "$fails"
