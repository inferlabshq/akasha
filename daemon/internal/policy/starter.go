package policy

// Starter is the policy document `akasha policy init` writes and `akasha setup`
// installs when a machine has none.
//
// It lives here rather than in cmd/akasha because two callers need it and only
// one of them is the CLI: setup installs it, and internal/setup cannot import a
// main package. Keeping it beside the engine that parses it also means the
// guard test in this package can assert that what ships actually parses and
// still carries the rules it is shipped FOR -- see starter_test.go. A default
// that silently loses a rule is the failure this file exists to prevent.
const Starter = `# Akasha retrieval policy — evaluated on every /retrieve, /assume, helper
# call and /grant, before any secret reaches an agent. First match wins.
# Effects: allow | deny | ask (native approval dialog; no answer = deny).
# Matchers (all optional, glob * ? supported, case-insensitive):
#   action: retrieve|broker|session|grant|inspect|describe|list|bind|purge
#   agent:   tool:   provider:   instance:
#   category: (SSN, CreditCard, APIKey, Credential, ...)
#   min_risk: low|medium|high|critical   (matches that level and above)
#   sandbox: true|false                  (only/never a supervised akasha run)
#   caller:  human|agent                 (the local CLI, or anything else)
#   brokerable: true|false               (provider has a per-operation route)
#
# "session" hands a credential over for a whole session; "broker" resolves one
# for a single operation and writes nothing to disk. Those two verbs ARE the
# session and per-operation modes — combine them with caller: to say "agents
# use production per operation, a person may take a session":
#
#   - {action: session, caller: agent, brokerable: true, effect: deny}
#   - {action: broker, effect: allow}
#
# Note on "tool:" and "agent:" — these arrive in the request body unless the
# caller presented an agent key, so they are ADVISORY. Use them to narrow a
# deny; never rely on one to grant access. Server-derived matchers (action,
# provider, instance, category, min_risk, sandbox, caller) are the ones an
# attacker can't choose.
#
# Edits apply immediately. Validate with: akasha policy validate
version: 1

# What happens when no rule matches: allow (advisory mode) or deny (lockdown).
default: allow

# Seconds an "ask" dialog waits before failing closed to deny.
ask_timeout_seconds: 60

# How strong an "ask" has to be: click (a dialog button) or passphrase.
# A passphrase is something a background process running as you cannot
# produce, which a button is not. Set one with: akasha policy passphrase
# It fails CLOSED: if none is configured, "ask" rules deny.
# ask_requires: passphrase

rules:
  # RETRIEVE (raw): returning plaintext into a caller's context — an agent's
  # vault_retrieve. Deny: this is the one verb that reaches ANY vaulted entry by
  # token, rather than a single provider's own credential.
  #
  # This rule is matched on the action alone, deliberately. It used to sit
  # below an exception for the credential helper (action: retrieve +
  # tool: akasha_helper -> allow), but "tool" is a request-body field, so any
  # caller that wrote that string satisfied the exception and read plaintext.
  # The broker now has its own action (below) and needs no exception here.
  - action: retrieve
    effect: deny
    reason: raw secret decryption is disabled — use the broker

  # BROKER: the git/aws credential helper resolves a secret for ONE operation,
  # writes nothing to disk, and logs every single use. It is still a read — the
  # daemon cannot tell the helper from an agent calling /resolve itself — so
  # this buys lifetime, disk residency and attribution, not "the agent never
  # sees it". Left to the default (allow) so routine git/aws work isn't
  # interrupted. To require approval for a specific case, add a rule here:
  #   - action: broker
  #     provider: aws
  #     instance: prod
  #     effect: ask
  #     reason: approve every production AWS operation

  # ASSUME materializes a credential for a whole session — broader than broker.
  #
  # Where a provider has a per-operation route, an agent does not need the
  # session form: it can use the credential through the broker without the
  # secret ever being written to disk. "brokerable" is read from the provider's
  # own template (a helper delivery plus a vending ownership mechanism), so this
  # rule covers aws/github/git/gitlab and does NOT touch ssh or gcp — they have
  # no alternative route, and denying them would just break them.
  #
  # The human keeps the session form: a person at a terminal wants AWS_PROFILE
  # set up, and is not the caller this is about.
  - action: session
    caller: agent
    brokerable: true
    effect: deny
    reason: an agent uses this per operation (broker) rather than holding a session credential

  # The daemon separately refuses to hand a verified agent a provider that would
  # deliver a raw secret in an env var — that one is not a preference. To gate
  # the remaining sessions as well:
  #   - action: session
  #     provider: ssh
  #     effect: ask
  #     reason: approve every ssh key handoff

  # GRANT carries the token's real risk (assume is always tagged critical, so it
  # can't be risk-gated) — ask only when delegating a high-risk secret onward.
  - action: grant
    min_risk: high
    effect: ask
    reason: delegating a high-risk secret needs human approval
  - action: grant
    effect: allow
    reason: routine low/medium delegation

  # BIND points a label at a secret. Creating a NEW label is routine (discover,
  # put and setup do it constantly) and is tagged "high". RE-pointing an
  # existing label at a different secret is tagged "critical": it silently
  # changes which credential every later assume and credential-helper call
  # uses, which is how an agent would redirect your own tooling at a credential
  # it controls. Left permissive so re-running discover/setup doesn't prompt;
  # uncomment to review every redirect:
  #   - action: bind
  #     min_risk: critical
  #     effect: ask
  #     reason: re-pointing an existing label changes which credential is used

  # PURGE garbage-collects orphaned discovery entries. Destructive:
  #   - action: purge
  #     effect: ask
`

// DeniesAgentSessionOnBrokerable reports whether this policy refuses an agent a
// SESSION credential for a provider that has a per-operation route.
//
// It exists so callers outside this package can ask the question by EVALUATION
// rather than by looking for a particular rule. The facts a rule matches on are
// unexported, deliberately, so a structural check ("is there a rule with
// caller: agent and brokerable: true?") is the only thing an outside caller
// could otherwise write — and that answers a different question. An operator who
// expresses the same posture with a broader `{action: assume, caller: agent,
// effect: deny}`, or with a default of deny, has the protection; a rule shadowed
// by an earlier allow does not. Only running the engine distinguishes those.
//
// Used by setup to tell a machine whose policy predates this rule that it is
// missing it, without claiming a specific spelling is the only correct one.
func (p *Policy) DeniesAgentSessionOnBrokerable() bool {
	if p == nil {
		return false
	}
	return p.Evaluate(Request{
		Action: "session", AgentID: "agent",
		AgentSource: Verified, ToolSource: ServerAssigned,
		Human:      false,
		brokerable: true,
		known:      FactBrokerable | FactProvider | FactInstance,
	}).Effect == EffectDeny
}
