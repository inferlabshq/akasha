# Akasha Plugin Format — login integrations

Status: **design** (v2 contract). Some blocks below exist in the shipped v1
contract; additions for v2 are marked **(v2)**. The reference implementation
lives in `daemon/internal/template/`. This document is the source of truth for
the format; the code follows it.

> **Writing a plugin for the current release?** Start with the
> [tutorial](writing-a-plugin.md) and copy from the working examples in
> [`daemon/templates/`](../daemon/templates/) — they use the shipped **v1**
> shape (`version: 1`, and ownership as a top-level `agent.own` list of
> `mechanism:` entries). The `version: 2` worked examples below and the
> `own:` / `select:` / `detect:` blocks tagged **(v2)** are the design target,
> **not yet parsed by the shipped daemon** — see the [status summary](#13-status-summary).

A "plugin" is a single YAML file describing one credential provider. Drop it in
`~/.akasha/templates/` (or `$AKASHA_TEMPLATES_DIR`) and the daemon can discover,
vault, deliver, and **own** that provider's credentials — with **no daemon
change and no PR**.

**There are no compiled-in providers.** aws, github, and a custom internal key
are all the same kind of thing: a YAML file loaded from disk through one uniform
path, with no privileged tier. Akasha ships a curated bundle as *data* (the
files in `daemon/templates/`, installed into `ShippedDir`), and a user file in
`UserDir` can add to or **override** any of it — a same-named file wins, there is
no rejection. Trust in the shipped bundle will come from **signatures**, never
from being embedded in the binary. Search path (earlier loaded first, later
overrides): `ShippedDir` then `UserDir`, or `$AKASHA_TEMPLATES_PATH` to set it
explicitly.

---

## 1. Principle: enumerate mechanisms, not providers

"Integrate with everything" is unreachable if the unit of integration is a
*provider* — there are thousands. It is reachable if the unit is a *delivery
mechanism* — there are about three. Every credentialed login reduces to two
small axes plus a selector:

```
            HOW THE SECRET REACHES THE TOOL          HOW THE AGENT ENV IS OWNED
            (deliver archetype)                      (ownership primitive)
            ─────────────────────────────            ──────────────────────────
  weakest   env      NAME=secret in environment      env     set session vars
            file     a file at a known path          config  own a config file
  strongest helper   per-use callback, reads stdout  decoy   blank the default path
            socket   long-lived protocol server
                                          ╲          ╱
                                       selector: how the consumer
                                       picks an instance
                                       (profile-name | host | none)
```

The daemon implements a **fixed, audited library of primitives** for each axis
(parsers, renderers, ownership executors, selectors). A plugin is **pure data**
that *selects and parameterises* those primitives by name — it can never
introduce procedure. That constraint is the trust boundary: a third-party plugin
is reviewable as data, not auditable as code. A genuinely new *mechanism* (some
tool with a bespoke credential protocol) is the only thing that requires a Go
change: one new primitive plus an enum value.

### Prefer the strongest deliverable mode

`helper`/`socket` are on-demand: the secret is **never at rest**, every access
is a daemon round-trip (per-use audit), and a TTL forces re-resolution. `file`
is materialised on a RAM-disk with a TTL. `env` is materialised and uncontrolled.
Modes are listed **best-first** in a plugin, and setup picks the strongest mode
that can be *owned* for a given agent harness. `helper` is the gold tier and the
one that delivers Akasha's actual guarantee — design plugins to support it where
the tool has a callback protocol.

---

## 2. Anatomy of a plugin

```yaml
kind: provider          # provider | discovery
name: <provider-name>   # [A-Za-z0-9._-]+ ; the label namespace ("aws:default")
version: 1

credential: { ... }     # what a secret of this provider IS
discover:  [ ... ]      # where existing instances already live (read-only)
deliver:   [ ... ]      # how the secret is handed to a consumer (best-first)
detect:    [ ... ]      # (v2) classifier patterns this provider contributes
mint:      { ... }      # optional: provider-native down-scoping
```

In **v1**, harness ownership is a separate top-level `agent:` block. In **v2**
that block is folded into each deliver mode's `own:` list (§5), so a mode
self-describes **render × own × select**. v1 `agent:` blocks remain accepted and
are interpreted as the `own:` of the first ow(n)able mode (§12, compatibility).

Two artifact kinds exist:
- **`provider`** — the full shape. `deliver`/`own` blocks write files and
  environment into agent sessions, so providers are the high-trust kind.
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
    instances: sections        # sections | keys | filename | single
    risk: high
    map:                       # credential field -> key in the source
      access_key_id: aws_access_key_id
      secret_access_key: aws_secret_access_key
      session_token: aws_session_token
```

`match:` (a classifier or matcher name, e.g. `pem-private-key`) narrows
`source: file` / `env-lines` to credentials that fit a shape.

---

## 5. `deliver` — how the secret reaches the tool

A list of modes, **best-first**. Each mode pairs a **render** spec (how to
express the secret) with, in v2, an **`own`** spec (how to make the agent's
environment resolve through this mode) and a **`select`** spec (how the consumer
picks an instance).

### Deliver archetypes (the `mode` enum)

| `mode` | archetype | at rest? | per-use audit | use for |
|---|---|---|---|---|
| `helper` | per-use callback; daemon emits a wire format to stdout | **no** | **yes** | AWS `credential_process`, git credential helper, kube `ExecCredential`, docker cred helper |
| `socket` | long-lived protocol server (named `contract`) | **no** | **yes** | `ssh-agent` and similar |
| `file` | materialised file at `path`, TTL-swept on RAM-disk | yes (RAM) | no | AWS shared-creds, GCP ADC json, kubeconfig, `.npmrc`, `.netrc` |
| `env` | exported `NAME=value` | yes | no | single-valued SaaS keys (`STRIPE_API_KEY`, `GITHUB_TOKEN`) |

### Render: wire formats (the `format` enum, for `helper`)

Generic emit mechanisms — **never provider names**. A provider is always a
template composing these.

- **`json`** — one JSON object on stdout (AWS `credential_process` shape).
  Built with `json.Marshal`, so secret content can never break output structure.
- **`kv-lines`** — sorted `key=value` lines (git's credential protocol shape).
  Values containing `\n`/`\r`/NUL are **refused** — a poisoned secret cannot
  inject extra protocol lines into the consumer.

`expiry:` names the output key that carries `now+ttl` (`rfc3339` or `unix`).
This is what forces the consumer to call back — and re-audit — instead of
caching forever.

### `own:` — ownership primitives **(v2)**

A mode's `own:` is a list of primitives applied to the agent harness so that,
inside an agent session, the tool resolves through this mode **by default** and
the plaintext path is dead. Credential *fields* are forbidden in `own:` by
schema — only paths and provider-callback wiring.

| primitive | shape | effect |
|---|---|---|
| `env` | `{env: {VAR: "{template}"}}` | set session env vars (paths/handles only) |
| `config` | `{env: VAR, path: f, per_instance: "...", preamble?: "...", shared_key?: VAR}` | generate a config file in the agent dir, point `env`'s VAR at it |
| `decoy` | `{env: VAR, empty: true}` *(or `path:`)* | point the tool's *default* credential location at an empty/blocking file so the plaintext path returns nothing |

`config` sub-keys:
- **`per_instance`** — rendered once per vaulted instance, concatenated.
  Placeholders: `{instance}`, `{binary}`, `{agent_dir}`, `{host}` (from select).
- **`preamble`** — emitted **once** at the top of the file (before instances).
  Used to *inherit* the user's real config, e.g. git's `[include] path = ~/.gitconfig`.
- **`shared_key`** — the env var (e.g. `GIT_CONFIG_GLOBAL`) names a file that
  **multiple plugins merge into**. github/gitlab/git each contribute a
  host-scoped section to one shared gitconfig. This is the general solution to
  "the tool reads exactly one global config file" — not a git special case; the
  same primitive serves `~/.docker/config.json` and a single kubeconfig later.

The AWS enforcement that ships today is exactly `config` (own `AWS_CONFIG_FILE`,
pointing its `credential_process` at `akasha helper aws`) **+** `decoy` (empty
`AWS_SHARED_CREDENTIALS_FILE`). v2 names these as reusable primitives so every
provider can have the same enforcement.

### `select:` — instance selection **(v2)**

How the consumer picks which instance to use. Generalises "instance".

```yaml
select: { by: profile-name, env: AWS_PROFILE }   # AWS: profile chosen by env var
select: { by: host, value: github.com }          # git: chosen by remote URL host
select: { by: none }                             # single-valued SaaS
```

---

## 6. `detect` — classifier patterns **(planned — not yet in the engine)**

> Not implemented in the alpha: a `detect:` block currently fails to load. The
> design below is the intended shape; track it as planned.

Adding a provider should also teach the classifier that provider's token shape,
so the *same file* that integrates GitLab also stops `gldt-…` deploy tokens from
leaking. Patterns are added to the rules engine at load; they never run
procedure.

```yaml
detect:
  - name: GitLab Deploy Token
    category: APIKey
    risk: high
    regex: '\bgldt-[A-Za-z0-9_-]{20,}\b'
  - name: Azure Client Secret
    category: APIKey
    risk: high
    regex: '...'
```

User-supplied `detect` patterns are additive and namespaced to the plugin in the
audit log (so "what added this detector" is on the record). They cannot weaken
or remove the shipped bundle's detectors.

---

## 7. `source` — where the secret comes from (resolvers) (v2)

`discover` (§4) *reads files*. A **resolver** *fetches from a secrets manager* —
1Password, HashiCorp Vault, Bitwarden, LastPass, AWS/GCP/Azure secret managers,
Doppler, or any REST API. This is how Akasha plugs into a user's existing custom
secret flow instead of demanding they migrate into Akasha's vault.

### Two postures

```yaml
source:
  - backend: onepassword-cli      # enum: a daemon primitive (see §9), never a command
    mode: on-demand               # on-demand (broker) | import
    ref: "op://{vault}/{instance}/credential"
    params: {vault: Private}
    map: {token: password}        # backend output field -> credential field
    cache: {ttl: 120}             # in-memory only, ≤ deliver TTL; never disk
```

- **`import`** — resolve once, vault the value locally, deliver from the vault.
  Akasha becomes the system of record. Simple, but duplicates a secret that
  already lives in a managed vault and forks rotation away from the source.
- **`on-demand` (broker, preferred default)** — the secret **stays** in the
  upstream manager. On each `helper` callback the daemon resolves it, emits the
  wire format, audits the access, applies the TTL, and stores **nothing** at
  rest. Composes directly with the `helper` deliver mode (§5). The pitch becomes
  *"keep your existing manager — Akasha is the agent-facing audit + ownership
  layer on top of it."* For HashiCorp Vault especially this is natural (Vault
  already issues short-lived secrets; Akasha adds per-agent identity + harness
  enforcement). Note the recursion: Akasha can use the AWS credential it already
  manages to resolve from AWS Secrets Manager.

### The command-execution trust model

A resolver runs a backend — i.e. it can cause **process execution or network
calls**. If a dropped `~/.akasha/templates/*.yaml` could carry a command string,
dropping a file would be remote code execution, detonating the "data, not code"
boundary the whole format rests on. Control is layered — every layer assumes the
ones above it failed:

1. **No commands in data — ever.** A plugin never contains argv or a command
   string. It *selects a named backend primitive* (§9); the Go primitive owns
   argv construction. The plugin supplies only **typed, schema-validated
   parameters** (item ref, field, vault path). This is the load-bearing control:
   it moves argv out of untrusted data and into reviewed code.
2. **No shell.** Execution is `exec.Command(bin, args...)` with discrete args —
   **never** `sh -c`. A param value of `; rm -rf ~` becomes one literal argv
   element, not a command. This eliminates the metacharacter-injection class
   entirely.
3. **Allowlisted, absolute, pinned binaries.** Each backend knows its binary
   (`op`, `vault`, `bw`, `lpass`, `aws`, `gcloud`, `az`). It is resolved from a
   **user/policy-configured absolute path**, optionally checksum-pinned — never
   from the inherited `$PATH`, never from a template-supplied path. A planted
   `op` on `$PATH` cannot hijack it.
4. **Argument hygiene.** Every substituted parameter passes a strict charset
   (the existing `safeName` `^[A-Za-z0-9._-]+$`, tightened per backend), rejects
   newlines/NUL, has a length cap, and argv uses a `--` end-of-options guard so a
   value beginning `-` can't be read as a flag (flag-injection defence).
5. **Capability is opt-in, per template, bound to a content hash.** Three tiers:
   - **shipped** (the signed bundle, reviewed by you) — may use any backend.
   - **user template** — using *any* backend requires a one-time **explicit human
     approval** surfaced in plain language (*"plugin `acme` wants to run `op` to
     resolve secrets — allow?"*), recorded against the file's SHA-256.
   - **default** — no resolver capability at all; file-reading discovery only.
   A silently-dropped file can **never** gain execution. If the file changes
   after approval (TOCTOU / swap), capability is revoked until re-approved.
6. **Scrubbed, minimal environment.** The backend process gets only the env vars
   it *declares* it needs (e.g. `OP_SERVICE_ACCOUNT_TOKEN`, `VAULT_ADDR`,
   `HOME`) — never the daemon's full env, never other vault secrets, never
   `AKASHA_*` keys. Working dir is a controlled temp, not the cwd.
7. **Egress control for the `http` backend.** Scheme must be `https`; the URL
   **host** must match a user/policy-configured allowlist (not template-supplied);
   off-allowlist redirects are refused. This closes the "resolver as exfil
   channel" hole — a template cannot POST the resolved secret to an attacker URL.
8. **OS sandbox + resource bounds.** Wall-clock timeout, stdout/stderr size caps,
   kill-the-process-group on exit, `no_new_privs`; `sandbox-exec` profile on
   macOS / seccomp+landlock or a namespace on Linux where available. Portable
   baseline (timeout + killpg + caps) always; OS sandbox as hardening.
9. **Output discipline.** stdout is parsed by a named parser primitive
   (json/kv-lines) with the line-control rejection from §5; only declared
   `map` fields are extracted; **nothing from stdout is logged**; stderr is
   captured for diagnostics, secret-scrubbed.
10. **Self-audit.** Every resolution is an audited event: template (by hash),
    backend, binary (absolute path + version), argv with secret-typed params
    redacted, agent identity, reasoning trace, exit code, duration. Akasha's
    core value, applied to itself.
11. **Caching bounds spawn frequency** (and biometric prompts, e.g. `op`'s Touch
    ID): in-memory only, TTL ≤ the deliver TTL, never on disk, cache hits
    audited. For non-interactive agent use, prefer a vaulted *service-account
    token* (itself a recursion: vault `OP_SERVICE_ACCOUNT_TOKEN`, use it to
    resolve everything else) over interactive biometric.
12. **Global kill switch / policy.** Resolvers are **off by default**
    (`resolvers.enabled = false`). Enterprise policy can pin the allowed
    backends, allowed binaries + checksums, and force approval.

### No arbitrary-`exec` backend (deliberate)

There is **no** generic `exec` backend (arbitrary binary + argv), by design.
Allowing a template to name the command to run would put a command back into the
data and defeat the whole data/code boundary, even behind an approval. If your
secrets manager isn't a named backend yet, the path is a small reviewed Go
addition (a new named backend), not an escape hatch — *"send a PR adding the
backend, don't ship an `exec` template."*

---

## 8. `mint` — provider-native down-scoping (optional)

Declares that the daemon can mint a *derived* credential that embodies its own
limits, issuer-enforced, via a named `contract`. Templates declare only which
contract applies and what constraints it accepts — the contract is a daemon
primitive.

```yaml
mint:
  contract: aws-sts-session-policy      # enum: aws-sts-session-policy | stripe-restricted-key
  constraints:
    services: {type: list}
    regions:  {type: list}
```

Status: declared in the contract and validated; **execution is not yet wired**.

---

## 9. Daemon primitive registry (the fixed, trusted core)

A plugin may reference only these names. Adding a value is a deliberate Go change
— the intended trust boundary. **No template can introduce a binary, a command,
a URL host, or a primitive that is not on this list.**

| axis | primitives (today) |
|---|---|
| discover sources | `ini`, `json`, `yaml`, `file`, `env-lines` |
| instance naming | `sections`, `keys`, `filename`, `single` |
| deliver modes | `helper`, `file`, `env`, `socket` |
| helper wire formats | `json`, `kv-lines` |
| expiry formats | `rfc3339`, `unix` |
| socket contracts | `ssh-agent` |
| mint contracts | `aws-sts-session-policy`, `stripe-restricted-key` |
| matchers | `pem-private-key` |
| **(v2)** ownership primitives | `env`, `config` (+`shared_key`, `preamble`), `decoy` |
| **(v2)** selectors | `profile-name`, `host`, `none` |
| source backends | `onepassword-cli` (implemented). Planned: `vault-kv`, `aws-secretsmanager`, `gcp-secret-manager`, `azure-keyvault`, `bitwarden-cli`, `lastpass-cli`, `http`. No arbitrary `exec` by design. |
| **(v2)** resolution modes | `on-demand` (broker), `import` |

Each backend primitive carries, in Go, its allowlisted binary name (or HTTP
client), its required-env whitelist, its parameter schema, and its output parser.
A plugin parameterises; it never extends.

---

## 10. Worked examples

### AWS — callback enforcement (config + decoy), v2 shape

```yaml
kind: provider
name: aws
version: 2
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
    select: {by: profile-name, env: AWS_PROFILE}
    static: {Version: 1}
    map: {AccessKeyId: access_key_id, SecretAccessKey: secret_access_key, SessionToken: session_token}
    expiry: {key: Expiration, format: rfc3339}
    own:
      - config:
          env: AWS_CONFIG_FILE
          path: aws.config
          per_instance: |
            [profile {instance}]
            credential_process = {binary} helper aws --instance {instance}
      - decoy: {env: AWS_SHARED_CREDENTIALS_FILE, empty: true}
```

### GitHub — shared, host-scoped gitconfig

```yaml
kind: provider
name: github
version: 2
credential:
  fields: {token: {secret: true, aliases: [value]}}
detect:
  - {name: GitHub PAT, category: APIKey, risk: high, regex: '\bghp_[A-Za-z0-9]{36}\b'}
deliver:
  - mode: helper
    format: kv-lines
    select: {by: host, value: github.com}
    static: {username: x-access-token}
    map: {password: token}
    expiry: {key: password_expiry_utc, format: unix}
    own:
      - config:
          shared_key: GIT_CONFIG_GLOBAL          # github + gitlab + git merge into ONE file
          path: git.gitconfig
          preamble: |
            [include]
                path = ~/.gitconfig                # inherit user identity/aliases
          per_instance: |
            [credential "https://{host}"]
                helper =                           # reset inherited helpers (kills keychain plaintext-PAT path)
                helper = "!{binary} helper github --instance {instance} get"
  - mode: env                                      # fallback for tools that only read GITHUB_TOKEN
    own: [{env: {GITHUB_TOKEN: "{token}"}}]
```

### Stripe — one line integrates a whole service (env tier)

```yaml
kind: provider
name: stripe
version: 1
credential: {fields: {secret_key: {secret: true}}}
detect:
  - {name: Stripe Secret Key, category: APIKey, risk: critical, regex: '\bsk_live_[A-Za-z0-9]{24,}\b'}
deliver:
  - mode: env
    own: [{env: {STRIPE_API_KEY: "{secret_key}"}}]
```

### 1Password / Vault broker — never stored, resolved per use (v2)

```yaml
kind: provider
name: datadog                       # the *consumer* is Datadog; the secret lives in 1Password
version: 2
credential: {fields: {api_key: {secret: true}}}
source:
  - backend: onepassword-cli        # daemon owns `op`'s argv; plugin gives only the ref
    mode: on-demand                 # secret stays in 1Password; resolved per helper call
    ref: "op://{vault}/datadog/{instance}/credential"
    params: {vault: Engineering}
    map: {api_key: password}
    cache: {ttl: 120}
deliver:
  - mode: env                       # broker → emit only when the agent actually needs it
    select: {by: none}
    own: [{env: {DD_API_KEY: "{api_key}"}}]
# Same shape with `backend: vault-kv` + `ref: "secret/data/datadog/{instance}"`,
# or `backend: aws-secretsmanager` + `ref: "prod/datadog/{instance}"`.
```

---

## 11. Trust & safety properties

- **Data, not code.** No conditionals or expressions beyond whitelist
  placeholder substitution and `if_set` presence checks. Plugins select named
  primitives only.
- **Secrets stay narrow.** A `secret` field reaches only the helper's stdout
  pipe to the consumer — never argv, the audit log, or disk. `own:` forbids
  credential fields by schema (paths only).
- **Uniform load, explicit override.** There is no privileged tier: a user file
  in `UserDir` overrides a shipped one of the same name (the override is logged),
  so you can fully own any provider. Invalid files are skipped with a logged
  reason. Every accepted template logs a one-line capability summary and its
  origin path. (Trust in the shipped bundle will come from signatures — a future
  bucket — not from load precedence.)
- **Strict parsing.** Unknown YAML keys are an error, so a typo'd block fails at
  load instead of being silently ignored.
- **Inherit without leaking.** `preamble` `[include]`s the user's real config so
  agent sessions keep identity/aliases; the `helper =` reset and `decoy` ensure
  the agent cannot reach a plaintext credential the human stored elsewhere.
- **Resolvers are code, so they are gated like code.** A `source` backend can
  execute or call out, so it is opt-in per template, approved by a human, bound
  to a content hash, run with a scrubbed env and no shell, against an
  allowlisted binary/host, and fully audited (§7). The default capability of a
  dropped template is *zero* execution.

### Signing & publisher trust (the marketplace)

Trust roots are **keys, not locations**. A plugin is signed by a publisher
(Ed25519 detached signature, a sibling `<file>.sig` that travels with it). A
sensitive capability (§6 `detect` aside — ownership today, resolvers later) is
auto-approved when the file carries a valid signature from a **trusted
publisher**; otherwise it needs explicit, hash-bound `akasha template trust`.

Three ways a template becomes trusted, unified in `trust.Approved`:
1. **Official signature** — signed by Akasha's embedded publisher key (the
   shipped bundle). This is the verification anchor, embedded as a *public key*
   (like a browser shipping root CAs) — not a compiled-in provider. → the
   shipped bundle is hands-off after install.
2. **A publisher the user added** — `akasha publisher add openclaw <key>`. The
   marketplace: an author signs their plugin, the user trusts that author once,
   and every plugin from them is accepted. No Akasha change, no service-X-only.
3. **Manual approval** — `akasha template trust <name>`, hash-bound, for
   unsigned local development.

Editing a signed file breaks its signature, so tamper revokes trust everywhere.
Author tooling: `akasha keygen`, `akasha template sign --key --publisher`,
`akasha template verify`. Provisioning the official root is a one-time ceremony
(`akasha keygen --out official`, paste into `internal/publisher/official.pub`,
`scripts/sign-bundle.sh official.key`, commit the `.sig` files); the private key
is the publisher's, never embedded.

---

## 12. v1 → v2 compatibility

- v1 top-level `agent:` (`env` + `config{path, per_instance}`) is still accepted
  and is interpreted as the `own:` of the first ownable deliver mode. Existing
  `aws.yaml` keeps working unchanged through the migration.
- New fields (`own`, `select`, `shared_key`, `preamble`, `decoy`, `detect`) are
  additive. A v1 daemon ignores nothing — strict parsing means a v1 binary
  rejects v2 keys, so bump the plugin `version` and gate on daemon version.
- Migration order for the reference build: add v2 primitives → migrate `aws.yaml`
  to v2 with **no behaviour change** (regression guard) → add `github.yaml` with
  full callback enforcement (proof the format generalises) → validate
  `shared_key` across the git family → fold `detect` patterns (absorbs the
  open classifier task for `gldt-…` / Azure secrets).

---

## 13. Status summary

| capability | state |
|---|---|
| five-block contract (`credential/discover/deliver/agent/mint`) | shipped (v1) |
| no compiled-in providers — uniform disk load, user overrides shipped | shipped |
| curated bundle shipped as data (`daemon/templates/`) + installer/CI wiring | shipped |
| `helper` (json/kv-lines), `file`, `env`, `socket` modes | shipped |
| env-ownership via structured `own:` mechanisms (no template-supplied command) | shipped for AWS + GitHub |
| ownership command-injection RCE closed (Go-rendered command, charset-validated params) | shipped |
| `akasha template validate/explain/list/new` (authoring loop) | shipped |
| trust gate: hash-bound approval for ownership (`template trust/untrust`) | shipped |
| signing: Ed25519 (`keygen`, `template sign/verify`) | shipped |
| publisher trust + signature-confers-approval (`publisher add/list/remove`) | shipped |
| official trust root provisioned + shipped bundle signed | **needs one-time key ceremony** |
| `own:` primitives (`config`+`shared_key`+`preamble`, `decoy`) | **v2 — planned** |
| `select:` selectors | **v2 — planned** |
| `detect:` classifier block | **v2 — planned** |
| `source` resolver contract + run-backend trust gating | shipped |
| resolver engine (no-shell, allowlisted bin, scrubbed env, timeout) + 1Password backend | shipped |
| on-demand broker wired into assume + helper (credential_process/git) | shipped |
| more source backends (vault-kv, aws/gcp/azure SM, http) | **planned** |
| resolver: http egress allowlist + OS sandbox hardening | **planned** |
| `import` posture + on-demand in-memory cache | **planned** |
| `mint` execution | declared, **not wired** |
