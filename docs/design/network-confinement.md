# Design note: network confinement for `akasha run`

Status: **spiked, not built.** The Linux mechanism is measured and works; the
plugin-format surface is the part that needs care, because it cannot be changed
after launch.

## The problem this closes

`akasha run` confines the filesystem and says so honestly on every launch:

```
akasha run: NOT confined: network. A compromised agent can still exfiltrate.
```

Exfiltration is the obvious half. The half that actually costs you a credential
is quieter: **the sandbox confines the process, not its deputies.**

A sandboxed agent cannot open `~/.aws/credentials` — but it can talk over
loopback to something that can. An MCP filesystem server running outside the
sandbox will read that file and hand back the contents. So will a local Postgres
with `COPY FROM`. So will anything else running as you with a network face and
filesystem reach.

Measured on a developer laptop, the services a sandboxed agent could reach:

| port | service |
|---|---|
| 7743 | akasha (profile applies) |
| 27017 | mongod — unauthenticated on localhost is the common dev default |
| 11434 | ollama |
| 13619 / 5000 / 7000 | app APIs |

`DenyDeputies` already exists for exactly this class, but it can only cover the
deputy it can name — today, the docker socket. Anything on TCP is unreachable to
a filesystem mask, because a mask is a mount and a port is not a file.

## What the spike measured

`bwrap --dev-bind / / --unshare-net`, alpine 3.20, as uid 1001.

| probe | today | `--unshare-net` |
|---|---|---|
| pathname unix socket to a server outside | reachable | **reachable** |
| loopback TCP to a service outside | reachable | **unreachable** |
| outbound DNS + HTTPS | HTTP 200 | blocked |
| interfaces inside | `lo eth0 …` | `lo` only |

The first row is the one the whole design rests on. **Pathname unix sockets are
filesystem objects and are not namespaced by the network namespace**, so
akasha's own run socket keeps working with the network fully removed. Abstract
sockets (`unix:abstract=…`) *are* namespaced and die — which is a bonus, since
`bwrap.go` already records an abstract session bus as the one keychain path a
filesystem mask cannot close.

Second spike, for the proxy mode:

| probe | result |
|---|---|
| `lo` state inside the namespace | `<LOOPBACK,UP,LOWER_UP>` — already up |
| listener on `127.0.0.1` inside | works |
| relay inside → bound unix socket → proxy outside | **PROXY-ANSWERED** |
| direct internet, same run | blocked |

So a child can be given an ordinary `HTTPS_PROXY=http://127.0.0.1:PORT` — which
every tool understands — while the only actual route off the machine is one
unix socket the operator chose. No `slirp4netns`, no veth pair, no root, no new
dependency.

## The division of labour

**akasha does not build a firewall, and must not.** It makes the operator's
proxy the only reachable thing; the proxy decides what is allowed.

- akasha: remove the network, bind exactly two pathname sockets (its own, and
  the proxy's), start the relay, set the proxy env vars.
- The operator: brings mitmproxy, Squid, tinyproxy, Envoy, a corporate proxy —
  whatever they already run.

That split is the same one the plugin format already uses: the template
declares, the operator decides, the daemon reads. It also keeps the enforcement
point auditable by someone other than us.

Note that the child can bypass the relay by connecting to the bound unix socket
directly. That is fine and worth writing down: **the relay is a convenience, not
a control.** Enforcement is at the proxy, and the proxy is reachable either way.
The control is that nothing *else* is.

## Three modes, as a policy key rather than three builds

```yaml
network: off      # today's behaviour, today's banner
network: none     # --unshare-net, nothing bound but akasha's socket
network: proxy    # --unshare-net, plus the operator's proxy
proxy: unix:///run/user/1000/egress.sock
```

`off` stays the default until the proxy path has been run against real agent
workloads. `none` is genuinely useful today for a run that only needs to broker
a credential and touch local files.

This is deliberately the same shape as the human-presence axis
(`ask_requires: click | passphrase | …`): one binary, one policy file, two
orthogonal axes. Presence governs **who may ask for a credential**; network
governs **where what they obtain can go, and which deputies they can recruit.**

## The part that needs care: the template declaration

An allow-list the user maintains by hand will drift out of sync with their
grants. Derive it instead — the same move as deriving the sandbox deny-list from
the templates' own declared credential locations:

```yaml
# templates/aws.yaml
network:
  hosts: ["*.amazonaws.com", "*.amazonaws.com.cn"]
```

Then `akasha run claude --assume aws:default` *implies* "this run may reach
AWS", and akasha emits that allow-list to the proxy rather than enforcing it.

**This is a public plugin-format surface and cannot be changed after launch.**
Decide before shipping:

- The emitted format. A proxy-agnostic file the operator adapts, or a
  first-class integration for one proxy? A file is more honest about who
  enforces, and does not make us responsible for a proxy's config grammar.
- Whether `hosts` accepts anything other than a hostname glob. Ports, CIDRs and
  URL paths each widen the surface and each need their own validation. Start
  with hostname globs only; the format is additive, so more can be added when
  someone needs it — and `min_daemon` should ship as an accepted-and-ignored key
  first so a later addition is not a one-way door.
- What an *undeclared* provider means. Under this codebase's fail-closed
  convention it must mean "no hosts", not "all hosts" — otherwise adding the key
  to a template narrows access and omitting it widens it, which is the same
  inverted polarity that made `brokerable` unsafe.

## HTTPS without interception

A CONNECT proxy sees the hostname, not the payload. So a hostname allow-list
needs **no TLS interception, no MITM, no certificate installed in the agent's
trust store.** `*.amazonaws.com` allowed and `evil.example.com` refused, with
nothing decrypted.

That is the property that makes this shippable to an individual developer rather
than only deployable by a security team, and it should be stated in the docs
where people decide whether to turn it on.

DNS is a free side effect: inside the namespace there is no resolver, and with a
CONNECT proxy the proxy resolves. DNS stops being an exfiltration channel
without anyone building anything.

## macOS

Different mechanism, same shape, and the renderer is already most of the way
there. `sbpl.go` emits `network-outbound` today for unix sockets:

```
(allow network-outbound (literal "/path/to/socket"))
```

SBPL's `network-outbound` also takes remote filters, so the profile becomes
deny-all plus an allow for the proxy endpoint. No relay is needed if the allow
can name a TCP endpoint directly — which would make the macOS path *simpler*
than the Linux one.

Unverified. Confirm before promising parity:

- whether a seatbelt profile can deny all network while still permitting the
  bound unix socket akasha already relies on;
- whether `(remote tcp "localhost:PORT")` behaves as expected under the
  `--dev-bind`-equivalent profile the renderer builds.

## What breaks, and who it breaks for

`--unshare-net` removes loopback services. That is the point, and it is also the
cost:

- a local Postgres, Redis, ollama, or a dev server the agent legitimately uses
- an MCP server the agent talks to over TCP — including, potentially, ones the
  user considers part of their setup rather than a deputy

So this is opt-in per run, and the failure has to be legible: a run that cannot
reach something should say *"network: proxy — 127.0.0.1:5432 is not reachable
from inside this run"*, not produce a connection-refused the user has to
diagnose. The banner already sets the precedent for saying what is and is not
confined; extend it rather than inventing a new channel.

## Sequencing

1. **`network: none`.** One bwrap flag, one policy key, one line in the banner.
   Small, immediately useful for credential-only runs, and it exercises the
   whole plumbing without touching the plugin format.
2. **The relay and `network: proxy`**, against a real proxy and a real agent
   session. Find out what an actual Claude Code run does when its only egress is
   a CONNECT proxy — this is where the surprises will be.
3. **macOS**, once the Linux shape has survived contact.
4. **The template `network:` key** last, because it is the only irreversible
   part and should be designed against evidence from steps 2 and 3 rather than
   against this document.
