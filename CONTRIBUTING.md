# Contributing to Akasha

Thanks for your interest. Akasha is alpha; contributions, plugins, and bug
reports are welcome.

## Security first

**Do not report vulnerabilities in public issues or PRs.** Follow
[SECURITY.md](SECURITY.md). Read [docs/THREATMODEL.md](docs/THREATMODEL.md)
before reporting — some behaviours (a *trusted* plugin running code) are by
design.

## Development

Requires Go 1.24+.

```bash
cd daemon
go build ./...
go vet ./...
go test ./...
```

PRs should keep `go vet` clean and add tests for new behaviour. The CI runs
build + vet + test on every PR.

## The one rule that shapes contributions

**A new *provider* is a plugin (data), not Go.** Integrating a service — AWS,
GitHub, Datadog, your internal tool — is a YAML file in the
[plugin format](docs/PLUGIN_FORMAT.md). It never requires a code change. If a PR
adds service-specific Go, that's the smell to reject.

What *does* belong in Go is a new **mechanism** — a parser, a deliver mode, an
ownership protocol renderer, or a `source` backend. These are the daemon's
fixed, reviewed primitives that plugins select by name. The line:

- new service → a plugin (no PR needed; or contribute it to the bundle),
- new *protocol/mechanism* → a small, carefully reviewed Go primitive.

This boundary is what keeps untrusted plugins safe to load. Two hard rules that
follow from it:

- **No template-supplied commands.** A plugin selects a named mechanism and
  supplies parameters; the daemon owns every binary, argv, and rendered command.
- **No arbitrary-`exec` backend.** If a secrets manager isn't a named backend
  yet, add the named backend — don't add an escape hatch.

## Contributing a plugin

Write it, validate it, and (optionally) sign it:

```bash
akasha template new myservice > myservice.yaml
akasha template validate myservice.yaml
akasha template explain  myservice.yaml      # see exactly what it does
```

See [docs/writing-a-plugin.md](docs/writing-a-plugin.md). To propose a plugin for
the shipped bundle, open a PR adding it under `daemon/templates/`.

## Commits

Keep messages descriptive (a `type(scope): summary` style is used throughout the
history). Sign off if your org requires DCO.
