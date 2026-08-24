# Akasha README demo — regenerate with:
#
#   ./docs/demo/demo-env.sh && vhs docs/demo/demo.tape
#
# Runs against the isolated environment demo-env.sh builds (synthetic
# credentials, temp HOME, keychain-isolated daemon). Nothing here touches a real
# vault. Every line of output is the real binary — nothing is staged or faked.

Output docs/demo/demo.gif

Set Shell bash
# Geometry: sized so the terminal stays FULL rather than showing a half-empty
# frame for most of the run, and so the text survives being scaled down on a
# phone. ~96 cols fits the longest command (the akasha exec line, ~71 cols).
# Interior height / 20px line pitch = 20 rows, measured off a rendered frame,
# so the 32-line session scrolls — which is what a terminal is supposed to do.
Set FontSize 16
Set Width 960
Set Height 440
Set Padding 18
# 24fps reads as smooth for typing and halves the frame count. It does NOT
# meaningfully shrink the file: at ~240KB the size is dominated by the scrolling
# (every scrolled frame is a full redraw, which defeats GIF frame-deltas), not
# by the frame rate. Measured, not assumed.
Set Framerate 24
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
