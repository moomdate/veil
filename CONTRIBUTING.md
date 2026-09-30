# Contributing to Veil

[ภาษาไทย](CONTRIBUTING.th.md)

Thanks for helping. Veil is security software whose users are often in a
hurry, so we care equally about **being safe** and **being easy to use**.

## Getting set up

You need Go 1.26 or later.

```sh
git clone https://github.com/moomdate/veil && cd veil
make test      # unit, CLI and canary end-to-end tests with the race detector
make lint      # golangci-lint and govulncheck
make fuzz      # fuzz the redactor for a minute
make build     # ./bin/veil
```

To try your build without touching your real vault, point it at a scratch
directory: `VEIL_HOME=/tmp/veil-dev ./bin/veil init`. On macOS, `make build`
signs the binary with the hardened runtime; a plain `go build` binary signs
itself on first run.

The web UI lives in `internal/web`: Go templates, one CSS file and one small
script, all embedded. There is no Node toolchain. Pages must work without
the script, and must never load anything from another origin (the CSP
forbids it).

## How the code is organized

Read [docs/architecture.md](docs/architecture.md) first. In short: every
operation goes through `internal/broker`, which applies `internal/policy`,
runs the action, redacts the output and writes the audit log.

## Rules for security-sensitive changes

- Only `vault`, `redact`, `runner`, `httpinject` and `web` (after Touch ID)
  may call `secret.Value.Reveal()`. The linter enforces it. If you think another
  package needs it, open an issue first.
- Anything that sends data back to an agent must go through the broker and
  the redactor.
- Adding an MCP tool, or a new way to inject a secret, needs a canary test
  in `test/e2e` that tries to extract the value through it.
- If you change what Veil protects against, update
  [docs/threat-model.md](docs/threat-model.md) in the same pull request.

## Writing style for anything users read

CLI output, errors, and docs follow the same rules as the UI:

- Use words people know: "allowed hosts", not "domain allowlist"; "hidden",
  not "redacted".
- Errors say what went wrong and what to do next, for example
  "no vault yet. Run `veil init` to create one."
- Never print a secret value, including in errors and debug output.
- Docs come in English and Thai (`*.th.md`). If you change one, update the
  other or say in your pull request that it needs translating.

## Code style

- Small packages with one job, dependencies passed in (no globals), so
  everything can be tested without the real keychain or network.
- Comments explain *why*, especially around security decisions.
- Tests are table-driven where it helps and name the attack they block.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `sec:`, `docs:`), which the changelog is built from.

## Releasing

See [docs/releasing.md](docs/releasing.md).

## Pull requests

Keep them focused. Fill in the checklist in the template. CI runs tests on
Linux and macOS, the linter, govulncheck, CodeQL, and a short fuzz run.
