# Changelog

All notable changes are listed here. This project follows
[Semantic Versioning](https://semver.org).

## v0.2.0 (2026-09-30)

- **Security:** on macOS the master key is stored with a Keychain access
  list that trusts only the Veil binary. Other programs, including
  `security find-generic-password`, now need your password.
- **Security:** Veil signs itself with the hardened runtime on first use
  (`veil protect`) and refuses to open the vault from an unprotected binary,
  so code can't be injected into it to read the key.
- `veil ui`: local web page to add, review, reveal (with Touch ID), edit and
  delete secrets, see activity and agents, and import `.env` files. Changing
  where a secret may go needs Touch ID or your password.
- `veil import FILE`: move secrets out of a `.env` file and delete it.
- Activity entries now say "you" for your own actions.
- New logo, and a usage guide with screenshots (`docs/usage.md`, Thai
  `docs/usage.th.md`).

## v0.1.0 (2026-09-30, not released separately)

First version.

- Encrypted vault (XChaCha20-Poly1305) with its master key in the OS keychain
- CLI: `init`, `add`, `list`, `rm`, `run`, `log`, `connect`, `mcp`
- MCP server with `list_secrets`, `run_with_secrets` and `http_request`;
  none of them returns a value
- Protection levels: Basic (commands), Scoped (HTTP to allowed hosts, headers
  only by default) and Guarded (reserved for approvals)
- Hides values and their base64, hex, URL and JSON encodings in all output
- Audit log of every use and refusal
- `veil connect` for Claude Code, Cursor and other MCP clients
