# Writing a Plugin

A plugin teaches Akasha how a service's credentials are shaped, where they live,
how to fetch them, and how to hand them to an agent — as a single YAML file.
Drop it in `~/.akasha/templates/` and it works: **no Akasha code, no PR.**

The one rule that makes this safe: you **select named mechanisms and supply
parameters — you never supply code.** The daemon owns every binary, parser,
renderer, and command. That's why an untrusted plugin can't execute anything.

The full field reference is [PLUGIN_FORMAT.md](PLUGIN_FORMAT.md); this is the
tutorial.

## Your first plugin

We'll integrate **Datadog**, brokering its API key live from 1Password so the
secret stays in 1Password and is never stored in Akasha's vault.

Create `~/.akasha/templates/datadog.yaml`:

```yaml
kind: provider
name: datadog
version: 1

# 1) What a Datadog credential IS.
credential:
  fields:
    api_key: {secret: true}

# 2) Where it comes from: resolve LIVE from 1Password on each use (broker).
#    The daemon owns the `op` binary; you only supply a reference.
source:
  - backend: onepassword-cli
    mode: on-demand
    ref: "op://Engineering/datadog/{instance}/credential"
    map: {value: api_key}   # backend output key -> credential field (this way round)
    cache: {ttl: 120}

# 3) How the agent receives it: the env var the Datadog SDK/CLI reads.
deliver:
  - mode: env
    env:
      DD_API_KEY: "{api_key}"
```

### Validate it

```console
$ akasha template validate ~/.akasha/templates/datadog.yaml
✓ valid — provider "datadog" (version 1)
  capabilities: runs:onepassword-cli writes:env
```

### See exactly what it does (no secret touched)

```console
$ akasha template explain datadog
CAPABILITIES
  runs backend: onepassword-cli (on-demand) ref "op://Engineering/datadog/{instance}/credential"
  delivers via: env

DRY RUN (placeholder secrets; nothing is read or written)
  would set env: DD_API_KEY=<api_key>
```

### Trust it, then use it

Delivering a credential (setting env vars or writing a session file), running a
backend, or owning an agent session are all high-trust actions, so a new provider
is gated until you approve it — once, bound to the file's SHA-256 (an edit
re-prompts). `akasha setup` offers this for the bundled providers in one step;
for one you add later:

```bash
akasha template trust datadog        # review + approve (hash-bound)
```

Now any agent that needs `DD_API_KEY` gets it brokered live from 1Password —
fetched per use, never stored.

### Test before you trust

`validate` and `explain` above are the *test-before-trust* workflow: `explain`'s
dry run lists every file and environment variable a template would produce —
rendered with visible placeholder secrets, reading and writing nothing — so you
can review a third-party template's full effect before approving it. Approval is
an explicit action; trust is never conferred by a template merely being present.

**Planned developer tooling** (not yet available — documented as direction):

- a **sandboxed dry-execution** (run the deliver/backend against a throwaway
  secret in a confined environment to observe real behaviour, not just the static
  manifest);
- a **diff-against-trusted** view so re-approving an edited template shows only
  what changed;
- a **template test harness** for authors (fixtures + expected rendered output).

Reach for these before trusting a template from a source you don't control.

## The building blocks

| block | declare | the daemon… |
|---|---|---|
| `credential` | the secret's fields (`secret`, `optional`, `aliases`) | knows what's sensitive |
| `source` *(opt)* | fetch from a manager (`backend`, `ref`, `map`) | runs the named backend (no shell), brokers live — **trust-gated** |
| `discover` *(opt)* | every location creds already live — files, the process environment | reads & vaults them on `discover`/`setup`. This block IS the audit: nothing outside it is read |
| `deliver` | how the agent receives it | materializes env/file, or answers a per-use callback |
| `agent.own` *(opt)* | route the agent's tooling through Akasha | Go-renders the callback; command is *always* the akasha binary |

**The one thing everyone gets backwards:** `source.map` and `deliver.map` are
written **source-key → credential-field**, so the credential field is the
*value*; `discover.map` is written **credential-field → source-key**, so there
it is the *key*. Get it wrong and `akasha template validate` says
`map <key> -> unknown field "<value>"`. Full note in
[PLUGIN_FORMAT.md § source](PLUGIN_FORMAT.md#7-source--resolve-from-a-secrets-manager-broker).

## Choosing a deliver mode

Pick the strongest one the target tool supports — `helper` is the gold tier.

| mode | how the tool gets it | at rest? | per-use audit | use for |
|---|---|---|---|---|
| `helper` | a per-use callback the daemon answers | **no** | **yes** | AWS `credential_process`, git credential helper |
| `file` | a file at a known path (RAM-disk, TTL) | yes | no | AWS shared-creds, kubeconfig |
| `env` | an exported variable | yes | no | most SaaS keys (Stripe, Datadog, Azure SP) |
| `describe` | non-secret facts *about* the credential | **n/a — no secret leaves** | **yes** | "which AWS account is this?" |

The simplest possible plugin is one `env` line:

```yaml
kind: provider
name: stripe
version: 1
credential: {fields: {secret_key: {secret: true}}}
deliver:
  - mode: env
    env: {STRIPE_API_KEY: "{secret_key}"}
```

The fullest example is the shipped `daemon/templates/aws.yaml`: it `discover`s
`~/.aws/credentials`, delivers via a `helper` (per-use) *and* a `file`, owns the
agent env with `credential-process` + `decoy` mechanisms, and `describe`s its
account number without ever handing over the credential — all data.

## Mandatory ownership (routing an agent through Akasha)

If a tool has a callback protocol, `agent.own` makes an agent session use Akasha
by default. You select a **protocol mechanism**; the command is always the
akasha binary (you can't write a command, so nothing can be injected):

```yaml
agent:
  own:
    - mechanism: credential-process     # AWS-style ini callback
      env: AWS_CONFIG_FILE
      file: aws.config
      section: "profile {instance}"
    - mechanism: git-credential-helper  # every git host
      env: GIT_CONFIG_GLOBAL
      file: git.gitconfig
      host: github.com
      inherit_user_gitconfig: true
    - mechanism: decoy                  # blank the tool's default cred path
      env: AWS_SHARED_CREDENTIALS_FILE
      file: credentials.empty
```

Mechanisms are **callback protocols, not services** — `git-credential-helper`
serves github, gitlab, gitea, … with no new code.

## Scaffold a new one

```bash
akasha template new myservice > ~/.akasha/templates/myservice.yaml
akasha template validate ~/.akasha/templates/myservice.yaml
```

## Publishing (signing)

Sign a plugin so anyone who trusts you gets it auto-approved (no per-template
approval):

```bash
akasha keygen --out mypublisher                       # keep mypublisher.key secret
akasha template sign myservice.yaml --key mypublisher.key --publisher mypublisher
# users run:  akasha publisher add mypublisher mypublisher.pub
```

Editing a signed file breaks its signature, so tamper is always caught.

## Reference

Every field, enum, and the full trust model: [PLUGIN_FORMAT.md](PLUGIN_FORMAT.md).
