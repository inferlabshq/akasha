# Security Policy

Akasha is a security tool, so we take reports seriously. Please read the
[Threat Model](docs/THREATMODEL.md) first — it defines what is in scope and lists
behaviours that are **by design** (a *trusted* plugin running code is expected,
not a bug).

> **Alpha software.** Akasha is pre-1.0. Do not use it to protect secrets you
> cannot rotate. Expect rough edges and known, documented limitations.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

- Preferred: GitHub **private vulnerability reporting** (the repo's
  Security → "Report a vulnerability" tab).
- Or email **security@getakasha.dev** with details and, if possible, a minimal
  reproduction.

Please include: affected version/commit, the trust boundary it crosses (does it
let an *untrusted* plugin execute code, own the environment, exfiltrate a secret,
or read the vault?), reproduction steps, and impact.

We aim to acknowledge reports within a few days (best-effort during alpha) and to
work toward a coordinated fix and disclosure. We'll credit reporters who want it.

## In scope

- An **untrusted** plugin (unsigned/unapproved, dropped in `~/.akasha/templates/`)
  achieving code execution, owning an agent session's environment, exfiltrating a
  secret, or reading vault contents.
- Command/arg injection in the resolver or ownership-config path.
- Recovering plaintext secrets from disk artifacts (vault, session files, logs).
- Signature/trust bypass (a plugin treated as trusted without a valid signature
  from a trusted publisher or an explicit, hash-matching approval).
- Privilege/identity confusion between agents in the audit/access path.

## Out of scope

- Anything listed under [Out of scope (by design)](docs/THREATMODEL.md#out-of-scope-by-design):
  a *trusted* plugin running code, a fully compromised host, the human reading
  their own secrets.
- The [known alpha limitations](docs/THREATMODEL.md#known-limitations-alpha--being-hardened)
  (backend sandboxing, `$PATH` binary resolution, `discover.path` scope) — these
  are already tracked; a report is welcome but won't be treated as a surprise.

## Supported versions

During alpha, only the latest release/`main` is supported. Security fixes land on
`main`.
