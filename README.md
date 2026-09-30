# Veil

**Let AI agents use your secrets without seeing them.**

[ภาษาไทย](README.th.md)

AI coding agents need API keys and tokens to do real work. Today that usually
means pasting keys into chat, or leaving them in `.env` files the agent can
read. Either way the value ends up in the model's context, in transcripts,
and in logs.

Veil keeps your secrets encrypted on your computer and lets agents use them
**by name**. The agent asks Veil to run a command or send a request; Veil
fills in the real value at the last moment, outside the agent, and hides it
if it shows up in the output.

```text
Agent:  http_request  POST https://api.stripe.com/v1/refunds
                      Authorization: Bearer {{secret:STRIPE_SECRET_KEY}}
Veil:   ✓ api.stripe.com is allowed for STRIPE_SECRET_KEY → sends it
Agent:  sees the response, never the key
```

> **Status: early (v0.2).** Veil works and is tested, but it has not had an
> independent security review. On macOS its master key can only be read by
> Veil itself; on Linux any program running as you can read it. See the
> [threat model](docs/threat-model.md) for exactly what's covered.

## Install

```sh
# From source (needs Go 1.26+, and Xcode command line tools on macOS)
go install github.com/moomdate/veil/cmd/veil@latest

# Homebrew and prebuilt binaries arrive with the first tagged release.
```

On macOS, the first `veil` command signs the binary with the hardened
runtime so no other program can inject code into it (no Apple account
needed). After that, macOS may ask for your password once to let Veil use
its key. You'll see that again after each update.

## Get started

```sh
veil init                                   # create your vault; its key goes in your system keychain
veil add STRIPE_SECRET_KEY --domain api.stripe.com -d "Stripe test key"
veil add GITHUB_TOKEN --tier basic --command "gh *"
veil connect claude                         # or: cursor, other
```

Then ask your agent something like *"list my secrets"* or *"open a PR with
gh"*. You never paste a value into the chat.

Prefer clicking? `veil ui` opens a page in your browser to add, review and
delete secrets, see what agents did, and import a `.env` file. It runs only on
your computer and locks after 15 minutes. Showing a value, or letting a secret
go somewhere new, asks for Touch ID or your password.

Already have a `.env` file? `veil import .env` moves it into Veil and offers
to delete the file.

`veil add` asks for the value at a hidden prompt, or reads it from a pipe
(`pbpaste | veil add NAME ...`). It never takes the value as an argument,
because arguments end up in your shell history.

## Protection levels

Every secret has one of three levels. Pick the strictest one that works.

| Level | How agents can use it | Good for |
|---|---|---|
| **Scoped** (default) | Only in HTTP requests to hosts you list. By default only in headers. | API keys: Stripe, OpenAI, GitHub API |
| **Basic** | As an environment variable for commands you allow (or any command). Output is scanned and the value hidden. | CLIs that read a token from the environment: `gh`, `psql` |
| **Guarded** | Like Scoped, and you approve each use. *Approval arrives in v0.4; until then agents can't use Guarded secrets.* | Production and billing keys |

Scoped secrets go in request **headers** only, unless you allow more with
`--allow-in url,body`. A value placed in a URL or body can be stored by the
server (in a gist, an issue, a log) and read back later, which would defeat
the point.

## Commands

| Command | What it does |
|---|---|
| `veil init` | Create your vault |
| `veil add NAME` | Store a secret (`--update` to replace one) |
| `veil list` | Show secrets and their rules, never values (`--json` for scripts) |
| `veil rm NAME` | Delete a secret |
| `veil run -s NAME -- cmd ...` | Run a command with Basic secrets in its environment |
| `veil log` | Show recent use: what was used, by which agent, what was blocked |
| `veil ui` | Manage everything in your browser |
| `veil import FILE` | Move secrets from a `.env` file into Veil |
| `veil protect` | Re-sign Veil against code injection (macOS; runs automatically) |
| `veil connect AGENT` | Set up Claude Code, Cursor, or print the MCP config |
| `veil mcp` | The MCP server agents start (you don't run this yourself) |

## What agents see

Veil gives agents three MCP tools. None of them returns a value.

- `list_secrets`: names, descriptions, protection, and how to use each one
- `run_with_secrets`: run a command with Basic secrets as environment variables
- `http_request`: send a request with `{{secret:NAME}}` placeholders

If a value appears in any output, the agent sees `[HIDDEN:NAME]` instead.
This covers the raw value and common encodings: base64 (also inside longer
base64), hex, URL-escaped, and JSON-escaped.

## Where things live

| Path | What |
|---|---|
| `~/.veil/vault.json` | Encrypted secrets and rules (XChaCha20-Poly1305) |
| `~/.veil/audit.log` | Every use, as JSON Lines, with names only |
| System keychain, service `veil` | The vault's master key. On macOS only Veil can read it. |

Set `VEIL_HOME` to use a different directory.

## Roadmap

- **v0.1**: vault, CLI, MCP server, redaction, host and command rules, audit log
- **v0.2** (now): master key only Veil can read (macOS), web UI at `veil ui`, import from `.env`
- **v0.3**: finer HTTP rules, per-agent access
- **v0.4**: approvals for Guarded secrets with Touch ID
- **v0.5**: Claude Code hooks, key rotation, encrypted backup

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see
[SECURITY.md](SECURITY.md). Please don't open a public issue for those.

## License

[Apache 2.0](LICENSE)
