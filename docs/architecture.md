# Architecture

[ภาษาไทย](architecture.th.md)

Veil is one Go binary. It acts as a CLI and a local web page for you, and as
an MCP server for agents. All three go through the same broker, so the rules
can't differ depending on who asks.

```text
 you ──► veil CLI ─────┐
 you ──► veil ui ──────┤  (web; reveal and loosening need Touch ID via presence)
                       ▼
 agent ─► veil mcp ──► broker ──► policy ──► runner ──────► child process
         (stdio)        │   │                 httpinject ──► HTTPS API
                        │   └──► redact (every output passes through)
                        ├──► vault ◄── keystore (OS keychain)
                        └──► audit log
```

## Packages

All code lives under `internal/`, so nothing is a public Go API yet.

| Package | Responsibility | Sees values? |
|---|---|---|
| `secret` | `Secret`, `Tier`, and `Value`, a type that can't be printed or serialized by accident | Holds them |
| `keystore` | Loads and saves the 32-byte master key. On macOS (cgo) it's a Keychain item that trusts only the Veil binary, and it refuses to work from a binary without the hardened runtime. Elsewhere it uses the Secret Service. `Memory` is for tests. | Key only |
| `presence` | Asks the person at the computer to confirm with Touch ID or their password, through LocalAuthentication, in Veil's own process. `Fake` is for tests. | No |
| `dotenv` | Parses `.env` files for import | No |
| `vault` | Encrypted file: one XChaCha20-Poly1305 blob, written atomically, `0600` | Yes, to encrypt |
| `policy` | Pure functions: may this secret go to this host, into this command, into this part of a request? | No |
| `redact` | Replaces values and their encodings with `[HIDDEN:NAME]`, in batch or streaming mode | Yes, to match |
| `runner` | Runs a command with secrets in its environment, captures output through the redactor, and enforces a timeout on the whole process group | Yes, to inject |
| `httpinject` | Fills `{{secret:NAME}}` placeholders after checking host and placement, never follows redirects, and redacts the response | Yes, to inject |
| `audit` | Append-only JSON Lines log with names only | No |
| `broker` | Opens the vault, applies policy, calls runner or httpinject, and records the audit event | No (passes `Value` through) |
| `mcpserver` | Three MCP tools on top of the broker | No |
| `web` | `veil ui`: templates, CSS and a small script, embedded. Session, CSRF, Host checks, strict CSP. | Yes, to show a value after `presence` confirms |
| `cli` | Cobra commands and terminal UI | No |

"Sees values" means the package calls `Value.Reveal()`. A lint rule keeps
that list from growing silently.

## Life of a request

An agent calls `http_request` with
`Authorization: Bearer {{secret:STRIPE_KEY}}` and
`https://api.stripe.com/v1/charges`.

1. `mcpserver` validates the input against the tool's JSON schema and calls
   `broker.HTTP` with the agent's name from the MCP client info.
2. `broker` opens the vault. It re-reads the file each time so changes made
   with the CLI apply immediately, and builds a redactor from every secret.
3. `httpinject` parses the URL, rejects placeholders in the host or in header
   names, then for each referenced secret checks `policy.CheckHTTP` (tier,
   `https`, allowed host) and `policy.CheckPlacement` (header, URL or body).
4. Only then are values filled in and the request sent, with redirects
   disabled.
5. The response body and headers go through the redactor. Transport errors,
   which can quote the URL, are redacted too.
6. `broker` writes one audit event (`used`, `denied` or `failed`) and returns
   the redacted response.

## Vault file format

```json
{"format": "veil-vault", "version": 1, "nonce": "<24 bytes, base64>", "ciphertext": "<base64>"}
```

The plaintext is a JSON array of secrets with their values. The associated
data is `veil-vault:v1`, so changing the version field breaks decryption.
Every save uses a fresh random nonce and replaces the file with an atomic
rename.

## Testing

| Layer | Where |
|---|---|
| Unit tests | Next to each package |
| Fuzzing | `internal/redact`: no leak for any value, surrounding text or encoding, and streaming output equals batch output for any chunk size |
| Canary end-to-end | `test/e2e`: a real MCP client runs exfiltration attempts, then the transcript, audit log and vault file are searched for every canary in every encoding |
| CLI | `internal/cli`: runs commands with an in-memory keystore |
| Web UI | `internal/web`: a real HTTP server; wrong Host, no session, reused link, missing CSRF, cross-origin, reveal and loosening without presence, invalid names, and that no page ever contains a value |

Run `make check` before sending a pull request.
