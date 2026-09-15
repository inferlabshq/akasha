#!/bin/bash
# Bootstrap an Akasha test container.
#   /bootstrap.sh raw        -> plaintext credential files left on disk
#   /bootstrap.sh protected  -> the same files escrowed with `akasha protect`
set -u
MODE="${1:-raw}"
export HOME=/root
export AKASHA_ALLOW_NEW_VAULT=1

exec >>/var/log/bootstrap.log 2>&1
echo "=== bootstrap $MODE $(date) ==="

# 1. session bus + secret service (akasha stores the vault key there on Linux)
eval "$(dbus-launch --sh-syntax)"
eval "$(printf 'akasha-test-pw' | gnome-keyring-daemon --unlock --replace --daemonize --components=secrets 2>/dev/null)"
{
  echo "export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'"
  echo "export GNOME_KEYRING_CONTROL='${GNOME_KEYRING_CONTROL:-}'"
  echo "export AKASHA_ALLOW_NEW_VAULT=1"
} > /run/akasha-env
. /run/akasha-env

# 2. fixtures + templates
if [ ! -d "$HOME/.aws" ]; then
  sh /seed.sh "$HOME" happy
  mkdir -p "$HOME/.akasha/templates"
  cp /w-templates/* "$HOME/.akasha/templates/" 2>/dev/null || true
  # a repo for the git task
  mkdir -p "$HOME/proj" && cd "$HOME/proj" || exit 1
  git config --global user.email dev@example.com
  git config --global user.name  dev
  git init -q . 2>/dev/null
  echo "hello" > README.md
  git add README.md && git commit -qm "initial commit"
  git remote add origin https://github.com/tanrah/proj.git
  cd / || exit 1
fi

# 3. agent key for the MCP server (vault must be opened before the daemon holds it)
if [ ! -f /run/akasha-agent-key ]; then
  akasha agent create llm-agent 2>&1 | awk '/^  Key: /{print $2}' > /run/akasha-agent-key
fi

# 4. daemon
akasha start >>/var/log/akasha.log 2>&1 &
for i in $(seq 1 30); do
  [ -S "$HOME/.akasha/akasha.sock" ] && break
  sleep 0.5
done
akasha status 2>&1 | head -5

# 5. vault what is on disk
if [ ! -f /run/akasha-discovered ]; then
  akasha discover all --yes 2>&1 | tail -5
  touch /run/akasha-discovered
fi

# 6. optionally take the plaintext away
if [ "$MODE" = "protected" ] && [ ! -f /run/akasha-protected ]; then
  akasha protect --yes "$HOME/.aws/creden""tials" "$HOME/.aws/con""fig" "$HOME/.env" "$HOME/.git-creden""tials" "$HOME/workplace/.env" 2>&1 | tail -10
  touch /run/akasha-protected
fi

echo "=== bootstrap done ==="
touch /run/akasha-ready
tail -f /dev/null
