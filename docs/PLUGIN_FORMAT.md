# Akasha Plugin Format — login integrations

A "plugin" is a single YAML file describing one credential provider. Drop it in
`~/.akasha/templates/` (or `$AKASHA_TEMPLATES_DIR`) and the daemon can discover,
vault, deliver, and **own** that provider's credentials — with **no daemon change
and no PR**.

**There are no compiled-in providers.** aws, github, and a custom internal key
are the same kind of thing: a YAML file loaded from disk through one uniform
path, with no privileged tier. Akasha ships a curated bundle as *data* (the files
in `daemon/templates/`, installed into `ShippedDir`); a user file in `UserDir`
can add to or **override** any of it — a same-named file wins, no rejection. Trust
in the shipped bundle comes from **signatures**, never from being embedded in the
binary. Search path (earlier loaded first, later overrides): `ShippedDir` then
`UserDir`, or `$AKASHA_TEMPLATES_PATH` to set it explicitly.

New here? Follow the [tutorial](writing-a-plugin.md); this document is the
reference.

---

## The stability & extension contract

The format is a **public contract** — templates you and the community write
against — so it is designed to be **stable and extensible without ever forcing a
breaking migration**.

- **Frozen core (`version: 1`, permanent).** The set of top-level blocks —
  `credential` · `discover` · `source` · `deliver` · `agent` — their
  field names, and their semantics do not change, move, or get renamed. **A
  template written today keeps working on every future daemon.**
- **Open extension surface (additive).** New capability is a new *named value* in
  the daemon's [primitive registry](#the-daemon-primitive-registry) — a deliver
  mode, wire format, ownership mechanism, discover parser, source backend.
  Templates select primitives **by name**; a template that uses a new
  one simply needs a daemon that ships it, and every existing template is
  unaffected.
- **The two ways to extend:** a new *service* → a YAML file (data, no code); a
  new *capability* → a named primitive in the registry. **Never** a new top-level
  block, a `version` bump, or a field rename.
- **Graceful degradation (new template → older daemon).** The guarantee above
  runs forwards; this one runs backwards. A daemon that meets a primitive it does
  not implement **drops that capability and keeps the rest of the template**,
  rather than rejecting the file. A provider that adds a deliver mode does not
  lose `assume`, its credential helper, and `exec --assume` on an older daemon —
  it loses exactly the new mode. What was dropped is reported by
  `akasha template list` and logged by the daemon; nothing degrades silently.

This is why "integrate with everything" is reachable: the unit of integration is
a *mechanism* (there are a handful), not a *provider* (there are thousands).

### What degrades, and what still fails

The line is **capability vs. meaning**, and it is drawn so that leniency can
never weaken a security property.

| Unrecognised… | Behaviour | Why |
|---|---|---|
| YAML **key** | **Fatal** | A key defines what the document *means*. An unknown one makes the file's intent unknowable — and this is why extension goes through named primitives rather than new keys. |
| `deliver[].mode`, or a known mode's own primitive (helper `format`, describe `contract`) | Degrades — that deliver entry is dropped | Costs one delivery route; the others still work. |
| A `describe` disclosure-list entry naming a fact this daemon's contract cannot produce | Degrades — that entry is dropped | The same skew one level down: a newer contract computes more facts. The facts this daemon *can* derive are still revealed. |
| `discover[].source` / `.instances` / `.match` | Degrades — that rule is dropped | The locations this daemon *can* read are still discovered. |
| `agent.own[].mechanism` | **Fatal** | Ownership is containment. `decoy` is what points `AWS_SHARED_CREDENTIALS_FILE` at an empty file so an agent cannot read your real credentials; silently dropping it would remove that protection while everything still looked fine. |
| `source[].backend` / `.mode` | **Fatal** | Dropping a backend makes the daemon fall through to the vault path, silently serving a stale local copy of a credential the template says must be fetched live from an upstream manager. |

Two rules make this safe to rely on:

1. **Only an unrecognised *name* degrades.** A malformed *known* primitive — a
   traversing `deliver.name`, an ini-breaking `agent.own.section`, a `kv-lines`
   key containing `=`, a missing required sub-field — is a bug or an attack, not
   a daemon that is behind, and stays fatal.
2. **Authoring stays strict.** `akasha template validate` rejects every
   unrecognised name, so a plugin author who types `mode: fille` is told rather
   than handed a template that quietly does less than it says. Leniency applies
   only when the daemon loads a bundle it did not author.

---

## The shipped shape — write this today

The shape the daemon parses now. Copy from `daemon/templates/`.

```yaml
kind: provider
name: github
version: 1
credential:
  fields:
    token: {secret: true, aliases: [value]}
deliver:
  - mode: helper                 # git calls back per fetch/push (kv-lines protocol)
    format: kv-lines
    static: {username: x-access-token}
    map: {password: token}
    expiry: {key: password_expiry_utc, format: unix}
  - mode: env                    # fallback for tools that only read GITHUB_TOKEN
    env: {GITHUB_TOKEN: "{token}"}
agent:                           # own the session so git routes through akasha per-op
  own:
    - mechanism: git-credential-helper   # a NAMED protocol — the daemon renders the command
      env: GIT_CONFIG_GLOBAL
      file: github.gitconfig
      host: github.com
      inherit_user_gitconfig: true
```

Ownership is a top-level **`agent.own`** list; each entry names a **mechanism**
(`git-credential-helper` | `credential-process` | `decoy`) and supplies only
structural params. **The daemon renders the callback command; the template never
writes it** — the property everything here preserves (see [§ Ownership](#agent--own-the-session)).

---

## 1. Principle: enumerate mechanisms, not providers

Every credentialed login reduces to two small axes plus a selector:

```
            HOW THE SECRET REACHES THE TOOL          HOW THE AGENT ENV IS OWNED
            (deliver archetype)                      (ownership mechanism)
            ─────────────────────────────            ──────────────────────────
  weakest   env      NAME=secret in environment      env     set session vars
            file     a file at a known path          config  own a config file
  strongest helper   per-use callback, reads stdout  decoy   blank the default path
```

The daemon implements a **fixed, audited library of primitives** for each axis
(parsers, renderers, ownership executors). A plugin is **pure data** that
*selects and parameterises* those primitives by name — it can never introduce
procedure. That constraint is the trust boundary: a third-party plugin is
reviewable as data, not auditable as code. A genuinely new *mechanism* (a tool
with a bespoke credential protocol) is the only thing that needs a Go change: one
new primitive plus an enum value — an additive registry entry, never a format
change.

### Prefer the strongest deliverable mode

`helper` is on-demand: the secret is **never materialised into the session** —
no file, no environment variable — every access is
a daemon round-trip (per-use audit), and a TTL forces re-resolution. Where the
credential lives between calls depends on the provider: with a `source` block it
stays in the upstream manager and Akasha stores nothing, and otherwise it stays
encrypted in the vault. What `helper` removes in both cases is the plaintext
copy sitting in the session for an agent to read. `file` is
materialised on a RAM-disk with a TTL. `env` is materialised and uncontrolled.
Modes are listed **best-first**; setup picks the strongest mode it can *own* for a
given agent harness. `describe` sits outside this ladder entirely — it hands back
non-secret FACTS about a credential, never the credential. `helper` is the gold tier and the one that delivers Akasha's
actual guarantee — support it wherever the tool has a callback protocol.

---

## 2. Anatomy of a plugin

```yaml
kind: provider          # provider | discovery
name: <provider-name>   # [A-Za-z0-9._-]+ ; the label namespace ("aws:default")
version: 1

credential: { ... }     # what a secret of this provider IS
discover:  [ ... ]      # where existing instances already live (read-only)
source:    [ ... ]      # optional: resolve LIVE from a secrets manager (broker)
deliver:   [ ... ]      # how the secret is handed to a consumer (best-first)
agent:     { own: [...] }  # own the agent's environment so it resolves through Akasha
```

Two artifact kinds:
- **`provider`** — the full shape. `deliver`/`agent.own` write files and env into
  agent sessions, so providers are the high-trust kind.
- **`discovery`** — read-only rules that locate credentials for an existing
  provider (carries `provider:` naming the target). Cannot deliver or own.

---

## 3. `credential` — what the secret is

```yaml
credential:
  fields:
    access_key_id:     {}                       # non-secret field
    secret_access_key: {secret: true}           # redacted, never logged
    session_token:     {secret: true, optional: true}
    token:             {secret: true, aliases: [value]}   # single-value labels store under "value"
```

| field key | meaning |
|---|---|
| `secret` | value is sensitive — never appears in argv, audit log, or disk; only in the helper's stdout pipe |
| `optional` | absence is not an error; omitted from rendered output |
| `multiline` | value may contain newlines (PEM keys); affects rendering/validation |
| `aliases` | alternate keys the stored map may use; the declared name wins when both exist |

---

## 4. `discover` — where instances already live

Read-only location rules. Each source names a **parser primitive** and how to
name the instances it yields.

```yaml
discover:
  - source: ini                # ini | json | yaml | file | env-lines
    path: ~/.aws/credentials   # ~ allowed; glob allowed for source:file
    instances: sections        # sections | keys | filename | filename-stem | single
    risk: high
    map:                       # credential field -> key in the source
      access_key_id: aws_access_key_id
      secret_access_key: aws_secret_access_key
      session_token: aws_session_token
```

`instances: filename` names each instance after the file it came from;
`filename-stem` drops the extension, so `~/.azure/prod.json` yields `prod`
rather than `prod.json`. Use the stem for any provider whose credentials carry
an extension — otherwise the extension travels into every label, every policy
rule and the delivered filename (`azure-prod.json.json`).

`match:` (a matcher name, e.g. `pem-private-key`) narrows `source: file` /
`env-lines` to credentials that fit a shape.

---

## 5. `deliver` — how the secret reaches the tool

A list of modes, **best-first**. Each mode pairs a **render** spec (how to express
the secret) with the wire format the consumer expects.

### Deliver archetypes (the `mode` enum)

| `mode` | archetype | at rest? | per-use audit | use for |
|---|---|---|---|---|
| `helper` | per-use callback; daemon emits a wire format to stdout | **no** | **yes** | AWS `credential_process`, git credential helper, kube `ExecCredential`, docker cred helper |
| `file` | materialised file at `path`, TTL-swept on RAM-disk | yes (RAM) | no | AWS shared-creds, GCP ADC json, kubeconfig, `.npmrc`, `.netrc` |
| `env` | exported `NAME=value` | yes | no | single-valued SaaS keys (`STRIPE_API_KEY`, `GITHUB_TOKEN`) |
| `describe` | non-secret FACTS derived from the credential (named `contract`, disclosed via `map`) | **n/a — no secret leaves** | **yes** | "which AWS account is this?" without assuming it |

### Render: wire formats (the `format` enum, for `helper`)

Generic emit mechanisms — **never provider names**.

- **`json`** — one JSON object on stdout (AWS `credential_process` shape). Built
  with `json.Marshal`, so secret content can never break output structure.
- **`kv-lines`** — sorted `key=value` lines (git's credential protocol shape).
  Values containing `\n`/`\r`/NUL are **refused** — a poisoned secret cannot
  inject extra protocol lines into the consumer.

`expiry:` names the output key that carries `now+ttl` (`rfc3339` or `unix`) — what
forces the consumer to call back (and re-audit) instead of caching forever.

---

## 6. `agent` — own the session

`agent.own` is a list of **ownership mechanisms** applied to the agent harness so
that, inside an agent session, the tool resolves through Akasha **by default** and
the plaintext path is dead. Credential *fields* are forbidden here by schema —
paths and callback wiring only.

### Shipped: named mechanisms (use these today)

Each entry names one mechanism and supplies structural params:

| mechanism | params | effect |
|---|---|---|
| `git-credential-helper` | `env`, `file`, `host`, `inherit_user_gitconfig` | write a gitconfig that host-scopes git's credential `helper` to `akasha helper <provider>`, optionally `[include]`-ing the user's real `~/.gitconfig` |
| `credential-process` | `env`, `file`, `section` | write an ini file whose `credential_process` key points at `akasha helper <provider>` (AWS and anything speaking that protocol) |
| `decoy` | `env`, `file` | point the tool's *default* credential path at an empty file so a plaintext credential the human stored elsewhere returns nothing |

The daemon renders the callback command; the template supplies only
charset-validated params. **There is no field in which a template can place a
command** — this is the finding-#1 RCE guarantee, and everything below preserves
it.

### Extending ownership — add a mechanism, not a config

A new *provider* on an existing protocol is already pure data (github, gitlab,
gitea all use `git-credential-helper`; any SaaS key uses `env`). A genuinely
*new ownership protocol* — a tool with its own config-file credential callback —
is a **new named mechanism**: a small, reviewed Go primitive added to the
registry, exactly like the three above. The daemon keeps owning the key *and*
the command, so a dropped template can never author one.

**Why not a general "config as data" form?** A form where a template writes
arbitrary config keys would let it name an *executable* key (git `helper`, ssh
`ProxyCommand`, aws `credential_process`, …). Gating that with a per-format key
allowlist is sound (fail-closed), but every key ever allowed needs a human to
judge "does this execute?" — a standing command-injection surface on a security
product, for generality that is rarely needed (the three mechanisms + `env`
cover the vast majority; the ownership edge cases are a short, enumerable list,
each a mechanism on demand). So a general `config:` form is **deliberately
deferred, not precluded**: because the format is frozen and additive, it can be
added later — as an additive `config:` directive that breaks no existing
template — if self-serve protocol extensibility becomes a proven need (most
safely alongside a signed marketplace that trust-gates it). Until then,
ownership grows by adding a reviewed mechanism.

---

## 7. `source` — resolve from a secrets manager (broker)

`discover` (§4) *reads files*. A **resolver** *fetches from a secrets manager* —
1Password, HashiCorp Vault, Bitwarden, AWS/GCP/Azure secret managers, or a REST
API — so Akasha plugs into a user's existing secret flow instead of demanding
they migrate into Akasha's vault.

```yaml
source:
  - backend: onepassword-cli      # a named daemon primitive (§9), never a command
    mode: on-demand               # on-demand (broker) | import
    ref: "op://{vault}/{instance}/credential"
    params: {vault: Private}
    map: {value: token}           # backend output key -> credential field
    cache: {ttl: 120}             # in-memory only, ≤ deliver TTL; never disk
```

> **Which side is the credential field?** `source.map` and `deliver.map` read
> **source-key → credential-field**: the *value* must be a field declared in
> `credential.fields`, and `akasha template validate` fails with
> `map <key> -> unknown field "<value>"` if it isn't. `discover.map` runs the
> other way — **credential-field → source-key** — because a discovery rule names
> the field it is filling and then says where in the file to find it. The rule
> of thumb: the credential field is on the side nearest the credential's own
> definition, so it is the value everywhere except `discover`. The output keys
> are the backend's, not yours: `onepassword-cli` runs `op read`, which returns a
> single value under the key `value`, so its map is always `{value: <field>}`.

- **`on-demand` (broker, preferred).** The secret **stays** upstream. On each
  `helper` callback the daemon resolves it, emits the wire format, audits, applies
  the TTL, and stores **nothing** at rest. The pitch: *"keep your existing manager
  — Akasha is the agent-facing audit + ownership layer on top."*
- **`import`.** Resolve once, vault locally, deliver from the vault. Simpler, but
  duplicates a secret that already lives in a managed vault.

### The command-execution trust model

A resolver runs a backend — it can cause process execution or network calls. If a
dropped `*.yaml` could carry a command string, dropping a file would be RCE. So:

1. **No commands in data — ever.** A plugin *selects a named backend primitive*
   (§9); the Go primitive owns argv. The plugin supplies only typed,
   schema-validated parameters (ref, field, vault path).
2. **No shell.** `exec.Command(bin, args...)` with discrete args — never `sh -c`.
   `; rm -rf ~` becomes one literal argv element.
3. **Allowlisted binaries, never template-supplied.** The backend's binary name
   is fixed in Go; a template cannot choose it. By default the name is resolved
   on `$PATH`, and a world-writable binary or containing directory is refused —
   that closes the usual PATH-hijack, but a non-world-writable `$PATH` entry is
   still trusted. Pin an absolute path with `AKASHA_<BACKEND>_BIN` to leave
   `$PATH` out of it entirely.
4. **Argument hygiene.** Strict charset, no newlines/NUL, length cap, `--`
   end-of-options guard (flag-injection defence).
5. **Capability is opt-in, per template, bound to a content hash.** Shipped
   (signed) may use any backend; a user template needs one-time plain-language
   human approval (*"plugin `acme` wants to run `op` — allow?"*) recorded against
   its SHA-256; default is *no* resolver capability. Editing the file revokes it.
6. **Scrubbed, minimal env.** Only declared vars (`OP_SERVICE_ACCOUNT_TOKEN`,
   `VAULT_ADDR`, `HOME`) — never the daemon's env, other secrets, or `AKASHA_*`.
7. **Egress control** for the `http` backend — `https` only, host on a
   user/policy allowlist, no off-allowlist redirects.
8. **Process bounds** — timeout, output caps, killpg. There is **no OS sandbox
   around a backend subprocess yet**: a trusted backend runs with your full
   privileges. `akasha run`'s sandbox confines the *agent*, not the resolver.
   (Planned; tracked in the threat model's known limitations.)
9. **Output discipline** — parsed by a named parser; only mapped fields
   extracted; nothing from stdout logged.
10. **Self-audit** — every resolution is an audited event (template hash,
    backend, binary, redacted argv, agent identity, exit, duration).

**No arbitrary-`exec` backend, by design.** Naming the command to run would put a
command back into data. If your manager isn't a named backend yet, the path is a
small reviewed Go addition (a new named backend), not an escape hatch.

---

## The daemon primitive registry

This is the **extension surface** — the fixed, additive set of names a plugin may
reference. Adding a value is a deliberate, reviewed Go change (a new primitive);
**no template can introduce a binary, command, URL host, or a primitive not on
this list.** A new entry never changes the format — it is how the format grows.

| axis | primitives (today) |
|---|---|
| discover sources | `ini`, `json`, `yaml`, `file`, `env-lines`, `env` (process environment), `url-lines` (`https://user:token@host`) |
| instance naming | `sections`, `keys`, `filename`, `single` |
| deliver modes | `helper`, `file`, `env`, `describe` |
| helper wire formats | `json`, `kv-lines` |
| expiry formats | `rfc3339`, `unix` |
| ownership mechanisms | `git-credential-helper`, `credential-process`, `decoy` |
| identity contracts (`describe`) | `aws-access-key-account-id` |
| matchers | `pem-private-key` |
| source backends | `onepassword-cli`. Planned: `vault-kv`, `aws-secretsmanager`, `gcp-secret-manager`, `azure-keyvault`, `bitwarden-cli`, `http`. No arbitrary `exec`, by design. |
| resolution modes | `on-demand` (broker), `import` |

Each backend primitive carries, in Go, its allowlisted binary, its required-env
whitelist, its parameter schema, and its output parser. A plugin parameterises;
it never extends.

---

## Worked examples (shipped shape)

### AWS — callback enforcement (credential-process + decoy)

```yaml
kind: provider
name: aws
version: 1
credential:
  fields:
    access_key_id: {}
    secret_access_key: {secret: true}
    session_token: {secret: true, optional: true}
discover:
  - source: ini
    path: ~/.aws/credentials
    instances: sections
    map: {access_key_id: aws_access_key_id, secret_access_key: aws_secret_access_key, session_token: aws_session_token}
deliver:
  - mode: helper
    format: json
    static: {Version: 1}
    map: {AccessKeyId: access_key_id, SecretAccessKey: secret_access_key, SessionToken: session_token}
    expiry: {key: Expiration, format: rfc3339}
  - mode: file
    name: "aws-{instance}.creds"
    render:
      - "[{instance}]"
      - "aws_access_key_id = {access_key_id}"
      - "aws_secret_access_key = {secret_access_key}"
    env: {AWS_SHARED_CREDENTIALS_FILE: "{path}", AWS_PROFILE: "{instance}"}
agent:
  own:
    - mechanism: credential-process
      env: AWS_CONFIG_FILE
      file: aws.config
      section: "profile {instance}"
    - mechanism: decoy
      env: AWS_SHARED_CREDENTIALS_FILE
      file: credentials.empty
```

### GitHub — host-scoped gitconfig

See [The shipped shape](#the-shipped-shape--write-this-today) above.

### Stripe — one line integrates a whole service (env tier)

```yaml
kind: provider
name: stripe
version: 1
credential: {fields: {secret_key: {secret: true}}}
deliver:
  - mode: env
    env: {STRIPE_API_KEY: "{secret_key}"}
```

### Datadog via 1Password — never stored, resolved per use

```yaml
kind: provider
name: datadog                       # the *consumer* is Datadog; the secret lives in 1Password
version: 1
credential: {fields: {api_key: {secret: true}}}
source:
  - backend: onepassword-cli        # the daemon owns `op`'s argv; the plugin gives only the ref
    mode: on-demand                 # secret stays in 1Password; resolved per helper call
    ref: "op://{vault}/datadog/{instance}/credential"
    params: {vault: Engineering}
    map: {value: api_key}           # `op read`'s single output fills the api_key field
    cache: {ttl: 120}
deliver:
  - mode: env
    env: {DD_API_KEY: "{api_key}"}
```

---

## Trust & safety properties

- **Data, not code.** No conditionals or expressions beyond whitelist placeholder
  substitution and `if_set` presence checks. Plugins select named primitives only.
- **The daemon owns every command.** A template never authors an executable
  command — ownership selects a named mechanism (the daemon renders the command),
  and resolvers select a named backend. This is why ownership grows by adding a
  reviewed mechanism, not a template-authored config (see §6).
- **Secrets stay narrow.** A `secret` field reaches only the helper's stdout pipe
  — never argv, the audit log, or disk. `agent.own` forbids credential fields by
  schema.
- **Strict parsing.** Unknown YAML keys are an error, so a typo fails at load
  instead of silently doing nothing. (This is also why new top-level blocks are a
  breaking change — hence the frozen core: extend via named primitives, not keys.)
- **Uniform load, explicit override.** No privileged tier: a `UserDir` file
  overrides a shipped one of the same name (logged). Invalid files are skipped
  with a logged reason.
- **Resolvers are code, so they are gated like code** — opt-in per template, human
  approved, hash-bound, scrubbed env, no shell, allowlisted binary/host, fully
  audited (§7).

### Signing & publisher trust (the marketplace)

Trust roots are **keys, not locations**. A plugin is signed by a publisher
(Ed25519 detached signature, a sibling `<file>.sig`). A sensitive capability
(owning the agent env; running a resolver) is auto-approved when the file carries
a valid signature from a **trusted publisher**; otherwise it needs explicit,
hash-bound `akasha template trust`.

Three ways a template becomes trusted (unified in `trust.Approved`):
1. **Official signature** — signed by Akasha's embedded publisher key; the shipped
   bundle is hands-off after install. The anchor is embedded as a *public key*
   (like a browser shipping root CAs), not a compiled-in provider.
2. **A publisher the user added** — `akasha publisher add <name> <key>`: an author
   signs their plugin, the user trusts that author once, and every plugin from
   them is accepted.
3. **Manual approval** — `akasha template trust <name>`, hash-bound, for unsigned
   local development.

Editing a signed file breaks its signature, so tampering revokes trust. Author
tooling: `akasha keygen`, `akasha template sign --key --publisher`,
`akasha template verify`.

#### Why the shipped bundle must be signed

The order in `trust.Approved` is what makes this matter across releases: a
publisher signature is checked **before** the hash-bound approval record.

- **Signed** — trust follows the *publisher*, not the bytes. A release that edits
  a template re-signs it, and every user stays trusted. No prompts.
- **Unsigned** — trust falls back to a record bound to the file's SHA-256. Any
  release that changes one byte of a template **silently revokes that provider's
  approval**, and the user discovers it at use time, mid-workflow:
  `template "aws" is not trusted yet`. Every release. Every provider they touch.

So an unsigned bundle is not merely "less convenient" — it makes routine upgrades
break working setups. The release workflow therefore **fails** rather than
shipping unsigned, unless the repository variable `ALLOW_UNSIGNED_BUNDLE=true`
says otherwise. `akasha status` also reports which providers are approved by
hash rather than by signature, so the state is visible before it bites.

#### Provisioning the official key (one-time, before the first tag)

`internal/publisher/official.pub` is embedded with `//go:embed`, so **the trust
root is fixed at build time**. A binary built before the key is committed can
never verify an official signature — which means this must land *before* the
first release tag, or v1 users are on the unsigned path permanently.

```bash
akasha keygen --out akasha-official
```

1. Commit `akasha-official.pub`'s contents to `daemon/internal/publisher/official.pub`.
2. Store `akasha-official.key` as the `AKASHA_SIGNING_KEY` repository secret.
3. Destroy the local private key copy; keep an offline backup somewhere durable.

Losing the private key means no future release can be signed under the embedded
root, and recovering requires shipping a new binary with a new embedded key —
which every user must install before their bundle verifies again. Treat it like
a root CA key, because that is what it is.

---

## Deliberately not in the format (and where the job is done)

- **Host/instance selection** — no `select:` block. Host-scoping is a mechanism
  field (`git-credential-helper`'s `host:`); profile selection is the file mode's
  `env`.
- **Classification / detection** — no per-template `detect:` block. Sensitivity is
  the classifier + `~/.akasha/patterns.yaml`. (A self-describing `detect:` is a
  plausible *future additive* block; it would ride the forward-compat gate below,
  not a format restructure.)
- **Multiple providers into one config file** (e.g. GitHub + GitLab into one
  gitconfig) — a **daemon-rendering** improvement, not a format one: the format
  already expresses it (each mechanism carries its own `host:`); the daemon merges
  directives targeting the same env var/file. No new key.
- **Forward-compatibility for a genuinely new block** — if one is ever justified,
  a `min_daemon` gate (so an older daemon skips a too-new template with a clear
  message instead of a parse error) is a **non-breaking daemon relaxation**,
  addable the day it's needed. Reserved, not built.

---

## Status summary

| capability | state |
|---|---|
| frozen-core contract (`credential/discover/source/deliver/agent`, `version: 1`) | **shipped** |
| no compiled-in providers — uniform disk load, user overrides shipped | **shipped** |
| curated bundle shipped as data (`daemon/templates/`) + installer/CI | **shipped** |
| deliver modes `helper` (json/kv-lines), `file`, `env`, `describe` | **shipped** |
| ownership named mechanisms (`git-credential-helper`, `credential-process`, `decoy`) — daemon-rendered command | **shipped** |
| `source` resolvers: engine (no-shell, allowlisted bin, scrubbed env, timeout) + `onepassword-cli`, on-demand broker | **shipped** |
| `akasha template validate/explain/list/new`; trust gate; Ed25519 signing + publishers | **shipped** |
| official trust root provisioned + shipped bundle signed | needs one-time key ceremony |
| multi-provider merge into one config file (GitHub + GitLab) | **shipped** — daemon-rendering only, no format change |
| general `config:` ownership-as-data primitive | **deliberately deferred** (see §6) — a standing command-injection surface not worth it now; addable additively later if proven needed |
| more source backends (vault-kv, aws/gcp/azure SM, http) + egress allowlist + OS sandbox | planned |
| graceful degradation of unknown primitives (capability drops, containment stays fatal) | **shipped** |
| provider-native down-scoping (`mint`) and long-lived protocol servers (`socket`) | **not in the format.** Removed pre-v1 rather than freezing names ahead of implementations; degradation makes re-adding them free |
| `min_daemon` forward-compat gate | reserved — only if a new block is ever added |
