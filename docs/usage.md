# Using Veil

[ภาษาไทย](usage.th.md)

A walkthrough of the everyday flow: store a secret, let an agent use it, and
see what happened. Screenshots use example data; none of the values are real.

## 1. Set up once

```sh
veil init                    # creates your vault; the key goes in your Keychain
veil connect claude          # or: cursor, other
```

On macOS the first `veil` command also protects the binary against code
injection. macOS may then ask for your password once so Veil can use its
key. Choose **Always Allow**, but only right after you ran `veil` yourself.

## 2. Add secrets

From the terminal:

```sh
veil add STRIPE_SECRET_KEY --domain api.stripe.com -d "Stripe test-mode key for the billing API"
veil add GITHUB_TOKEN --tier basic --command "gh *" -d "Push branches and open PRs on my repos"
```

Veil asks for the value at a hidden prompt, so it never lands in your shell
history.

Or open the web page with `veil ui`:

![The Secrets page lists each secret with its protection, where it can go, and when it was last used](images/ui-secrets.jpg)

**Add secret** opens a panel. Type the name any way you like
(`openai-api key` becomes `OPENAI_API_KEY`). If the name matches a service
Veil knows, it suggests the right host:

![Adding a secret: Scoped is preselected, and Veil suggests api.openai.com for an OpenAI key](images/ui-add-secret.jpg)

Pick a protection level:

| Level | Use it for |
|---|---|
| **Scoped** (recommended) | API keys. Only sent in requests to the hosts you list, in headers only unless you allow URL or body. |
| **Basic** | Tools that read a token from the environment, like `gh` or `psql`. Limit it to specific commands when you can. |
| **Guarded** | Production and billing keys. You'll approve each use (approvals arrive in a later version). |

## 3. Already have a `.env` file?

```sh
veil import .env
```

Or use **Import .env** in the web page. You review every secret before
anything is saved. Veil guesses the protection from the name, skips values
too short to hide reliably, and offers to delete the file afterwards.

![Import review: OPENAI_API_KEY and SENDGRID_API_KEY become Scoped to their APIs; DEBUG is skipped as too short](images/ui-import.jpg)

## 4. Let the agent use them

Talk to your agent normally. Never paste a value into the chat.

> *"list my secrets"*
>
> *"Use STRIPE_SECRET_KEY to list the last 5 Stripe customers"*
>
> *"Open a PR for this branch with gh"*

The agent sees names and rules, never values:

```jsonc
// what list_secrets returns to the agent
{ "name": "STRIPE_SECRET_KEY",
  "description": "Stripe test-mode key for the billing API",
  "protection": "scoped",
  "allowed_hosts": ["api.stripe.com"],
  "how_to_use": "http_request to api.stripe.com with {{secret:STRIPE_SECRET_KEY}} in the header" }
```

To call Stripe, the agent writes a placeholder and Veil fills it in after
checking the host:

```jsonc
// http_request, as the agent sends it
{ "method": "GET",
  "url": "https://api.stripe.com/v1/customers?limit=5",
  "headers": { "Authorization": "Bearer {{secret:STRIPE_SECRET_KEY}}" } }
```

If a value ever shows up in output, the agent sees `[HIDDEN:NAME]` instead:

```text
$ veil run -s GITHUB_TOKEN -- sh -c 'echo token=$GITHUB_TOKEN'
token=[HIDDEN:GITHUB_TOKEN]
veil: hid 1 secret value(s) in the output
```

## 5. See what happened

The **Activity** page (or `veil log`) shows every use, every hidden value,
and every attempt Veil blocked, with the reason:

![Activity: a gh command that hid a token, a git push blocked by the command rule, and a request to webhook.site blocked because only api.stripe.com is allowed](images/ui-activity.jpg)

**Agents** shows which tools have used Veil, and how to connect another:

![Agents: Claude Code and Cursor with their recent use, plus the commands to connect more](images/ui-agents.jpg)

## 6. Look at or change a secret

Click a secret to see exactly what agents see, and how they use it:

![Secret detail: the value is hidden behind a veil pattern with a Reveal button; below are the description, allowed host, and the placeholder an agent uses](images/ui-secret-detail.jpg)

- **Reveal** asks for Touch ID or your password, shows the value for 10
  seconds, then hides it again.
- **Edit rules** asks for Touch ID only if the change lets the secret go
  somewhere new, such as a new host or a weaker protection level.
- **Replace value** and **Delete** are in the same panel. Delete asks you to
  type the name.

When you're done, click **Lock**, or leave it; the page locks itself after 15
minutes.

## Troubleshooting

| You see | What to do |
|---|---|
| `no vault yet` | Run `veil init`. |
| macOS asks for your password for "veil" | Expected after installing or updating Veil. Allow it only if you just ran `veil`. |
| `this copy of Veil isn't protected` | Run `veil protect` (normally automatic). |
| An agent says a secret "can't be sent to" a host | That host isn't allowed. Add it with **Edit rules** if you trust it. |
| The web page says "This link has expired" | Each `veil ui` link works once. Run `veil ui` again. |
