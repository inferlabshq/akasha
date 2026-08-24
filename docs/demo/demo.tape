# Akasha README demo — regenerate with:
#
#   ./docs/demo/demo-env.sh && vhs docs/demo/demo.tape
#
# Runs against the isolated environment demo-env.sh builds (synthetic
# credentials, temp HOME, keychain-isolated daemon). Nothing here touches a real
# vault. Every line of output is the real binary — nothing is staged or faked.

Output docs/demo/demo.gif

Set Shell bash
Set FontSize 15
Set Width 1180
Set Height 660
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

# Point the shell at the demo environment. AKASHA_AGENT_KEY is cleared because
# the recording shell may inherit one from an agent session; the demo runs as
# the local human.
Hide
Type "export HOME=/tmp/akdemo/home PATH=/tmp/akdemo/bin:$PATH" Enter
Type "unset AKASHA_AGENT_KEY AKASHA_AGENT_ID" Enter
Type "cd ~ && clear" Enter
Show

# Short: the first frame of the GIF is what a still preview shows, so the
# recording should open on the command rather than on an empty prompt.
Sleep 150ms

# 1. Find what is already lying around in plaintext. This prompts before it
#    takes anything — nothing is vaulted without an answer, which is worth
#    showing rather than skipping with -y.
Type "akasha discover all" Sleep 500ms Enter
Sleep 3500ms

# 2. Consent, and it takes possession.
Type "y" Sleep 600ms Enter
Sleep 3s

# 3. What an agent can now reach, by name rather than by value.
Type "akasha list" Sleep 400ms Enter
Sleep 2500ms

# 4. The point: a command runs with the credential, and the secret is never in
#    the session. The key is materialised to a TTL-swept file for the duration
#    of this one command and swept afterwards.
Type "akasha exec --assume ssh:demo_key -- sh -c 'echo using $SSH_KEY_PATH'" Sleep 400ms Enter
Sleep 3s

# 5. Every access is on the record — and the log carries a token DIGEST, not the
#    secret, so reading the audit trail hands an attacker nothing to try.
#    tail -9 is exactly one complete record.
Type "akasha logs | tail -9" Sleep 400ms Enter
Sleep 4s

Sleep 1500ms
