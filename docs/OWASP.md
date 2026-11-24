# Akasha and the OWASP Top 10 lists

How Akasha relates to the
[OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/top-10-for-llm-applications-2026/)
and the
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/top-10-for-agentic-applications-2026/),
as read in November 2026.

Akasha is about credentials on a developer's machine, so it bears on some of these
and not on others. Nothing here is a claim of compliance or coverage, and OWASP has
not reviewed it. The [threat model](THREATMODEL.md) is the authority where this
page is shorter than it.

- **Reduces** — makes the risk smaller for credentials, with the limit stated.
- **Limits the damage** — does not stop it, but shrinks what it can reach or leaves
  a record.
- **Not addressed** — use something else.

Two limits apply to every row. The broker returns the real credential to whatever
calls it inside a run, so it buys attribution and keeps plaintext off disk; it does
not contain a compromise. And a process running as you that goes after Akasha
itself can open a vault that has no passphrase.

## Agentic applications

| Risk | Akasha | How, and where it stops |
|---|---|---|
| ASI01 Agent Goal Hijack | Limits the damage | A hijacked agent in a run reaches only the credentials granted with `--with`, and each brokered use is recorded. It can misuse those. The network is open unless you pass `--network`. |
| ASI02 Tool Misuse and Exploitation | Limits the damage | Policy can allow, deny or ask per provider and per action. It does not see which command a tool then runs. |
| ASI03 Identity and Privilege Abuse | Reduces | Each run has its own identity and key, denied everything not listed, and revoked when the run ends. Identity is a same-user bearer key, not attestation, and the underlying credential is the one you already had. |
| ASI04 Agentic Supply Chain Vulnerabilities | Reduces, narrowly | Provider plugins are signed data with no command field, and an edited one loses its trust. Akasha does not check MCP servers, skills, packages or models. |
| ASI05 Unexpected Code Execution | Limits the damage | Inside a run, credential files and the vault are hidden, and shell startup files and login items are read-only. The code still runs, and your project stays writable. |
| ASI06 Memory & Context Poisoning | Not addressed | |
| ASI07 Insecure Inter-Agent Communication | Little | Grants pass one value between agents on one daemon, single-use and optionally expiring. The tool name is the caller's word, and messages between agents are not inspected. |
| ASI08 Cascading Failures | Little | Separate runs hold separate credentials, and a run's access ends with it. Nothing detects a cascade. |
| ASI09 Human-Agent Trust Exploitation | Little | `ask` puts a person in front of a credential, optionally with a passphrase an agent cannot read. A person can still approve the wrong thing. |
| ASI10 Rogue Agents | Limits the damage | The hash-chained audit log shows what was brokered to which run. Nothing detects a rogue agent, and use that goes around Akasha is not recorded. |

## LLM applications

| Risk | Akasha | How, and where it stops |
|---|---|---|
| LLM01 Prompt Injection | Limits the damage | Same as ASI01. Akasha does not detect or stop injection. |
| LLM02 Sensitive Information Disclosure | Reduces | `protect` takes a plaintext file off disk, and `wrap` replaces detected secrets in text with tokens. Detection misses things, and a granted credential can be read by asking the helper for it. |
| LLM03 Excessive Agency | Reduces, for credentials | An agent gets the credentials a run names and no others. What a credential can do at the provider is unchanged. |
| LLM04 Supply Chain | Reduces, narrowly | Same as ASI04. |
| LLM05 Data and Model Poisoning | Not addressed | |
| LLM06 Unbounded Consumption | Not addressed | |
| LLM07 Misinformation | Not addressed | |
| LLM08 Hidden Context Exposure | Little | Vaulted values can stay out of prompts as tokens. System prompts and other context are not protected. |
| LLM09 Vector and Embedding Weaknesses | Not addressed | |
| LLM10 Improper Output Handling | Not addressed | |

## What would change a row

- SSH and other credentials with no per-use route are delivered as files, or not
  at all. A run refuses them.
- Short-lived, scoped credentials from the provider would strengthen ASI03 and
  LLM03. Akasha does not mint credentials.
- Recording use that bypasses Akasha would strengthen ASI10.
