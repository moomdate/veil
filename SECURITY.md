# Security policy

[ภาษาไทย](SECURITY.th.md)

Veil exists to keep secrets away from AI agents, so we treat any way to get
a value out as a serious bug.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through
[GitHub security advisories](https://github.com/moomdate/veil/security/advisories/new).

Include what you did, what you expected, and what happened. A failing test
in the style of `test/e2e/canary_test.go` is the most useful thing you can
send. Never include real secret values.

We aim to acknowledge reports within 3 days and to ship a fix or a clear
plan within 30 days. We'll credit you in the release notes unless you'd
rather we didn't.

## In scope

- Any way for an agent using Veil's MCP tools to obtain a secret value,
  including by encoding, splitting or reflecting it
- Sending a secret to a host, request part or command its rules don't allow
- Reading or changing the vault without the master key
- Secret values appearing in the audit log, error messages or `veil` output
- Using the web UI to reveal a value or loosen a rule without Touch ID, or
  reaching it from another website
- Reading the master key on macOS without the Keychain asking the user

Gaps already listed in [docs/threat-model.md](docs/threat-model.md#known-gaps)
are known. New ways to exploit them, or ideas to close them, are still
welcome.

## Supported versions

Until 1.0, only the latest release gets security fixes.
