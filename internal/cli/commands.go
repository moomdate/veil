package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/mcpserver"
	"github.com/moomdate/veil/internal/policy"
	"github.com/moomdate/veil/internal/secret"
	"github.com/moomdate/veil/internal/vault"
)

func (a *app) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create your vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.broker.Init(); err != nil {
				if _, openErr := a.broker.Vault(); openErr == nil {
					a.ui.success("Your vault is already set up at %s", VaultPath(a.env.Home))
					return nil
				}
				return err
			}
			a.ui.success("Created your vault at %s", VaultPath(a.env.Home))
			if a.env.KeyAppOnly {
				a.ui.success("Saved its key in your Keychain, where only Veil can read it")
			} else {
				a.ui.success("Saved its key in your system keychain")
				a.ui.warn("On this system, other programs running as you can read that key. See docs/threat-model.md.")
			}
			a.ui.println()
			a.ui.println("Next:")
			a.ui.printf("  %s   store your first secret\n", a.ui.bold("veil add GITHUB_TOKEN"))
			a.ui.printf("  %s     let Claude Code use it\n", a.ui.bold("veil connect claude"))
			return nil
		},
	}
}

func (a *app) addCmd() *cobra.Command {
	var (
		desc     string
		tier     string
		domains  []string
		commands []string
		allowIn  []string
		update   bool
	)
	cmd := &cobra.Command{
		Use:   "add NAME",
		Short: "Store a secret",
		Long: `Store a secret. The value is read from a hidden prompt, or from stdin when
piped, and never from a command-line argument (those end up in your shell
history).

Protection:
  basic    agents can run approved commands with it as an environment variable
  scoped   only sent in HTTP requests to the hosts you allow (recommended)
  guarded  like scoped, and you approve each use (coming in a later version)`,
		Example: `  veil add STRIPE_SECRET_KEY --domain api.stripe.com
  veil add GITHUB_TOKEN --tier basic --command "gh *"
  veil add MAPS_KEY --domain maps.googleapis.com --allow-in url
  pbpaste | veil add OPENAI_API_KEY --domain api.openai.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToUpper(strings.ReplaceAll(args[0], "-", "_"))
			if err := secret.ValidateName(name); err != nil {
				return err
			}
			v, err := a.broker.Vault()
			if err != nil {
				return err
			}
			if _, err := v.Get(name); err == nil && !update {
				return fmt.Errorf("%s: %w", name, vault.ErrExists)
			} else if err != nil && update {
				return err
			}

			t := secret.Tier(strings.ToLower(tier))
			if !cmd.Flags().Changed("tier") && a.ui.tty {
				if t, err = a.askTier(); err != nil {
					return err
				}
			}
			if t != secret.Basic && len(domains) == 0 && a.ui.tty {
				if domains, err = a.askDomains(name); err != nil {
					return err
				}
			}
			for i, d := range domains {
				if domains[i], err = policy.NormalizeDomain(d); err != nil {
					return err
				}
			}

			value, err := a.readValue(name)
			if err != nil {
				return err
			}
			s := secret.Secret{Name: name, Value: value, Description: desc, Tier: t, Domains: domains, Commands: commands, AllowIn: allowIn}
			if t == secret.Basic {
				s.Domains, s.AllowIn = nil, nil
			}
			action := "add"
			if update {
				action = "update"
				err = v.Update(s)
			} else {
				err = v.Add(s)
			}
			if err != nil {
				return err
			}
			a.broker.Record(audit.Event{Agent: audit.You, Action: action, Secrets: []string{name}, Outcome: audit.Changed})

			a.ui.success("Saved %s (%s). Agents can use it now.", a.ui.bold(name), t.Label())
			if t == secret.Guarded {
				a.ui.warn("Guarded secrets need approval, which this version can't ask for yet, so agents can't use it until then.")
			}
			if desc == "" {
				a.ui.note("Tip: add --desc \"what it's for\" so agents pick the right secret.")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&desc, "desc", "d", "", "what the secret is for (agents can read this)")
	f.StringVarP(&tier, "tier", "t", string(secret.Scoped), "protection: basic, scoped or guarded")
	f.StringArrayVar(&domains, "domain", nil, "host the secret may be sent to, e.g. api.stripe.com or *.amazonaws.com (repeatable)")
	f.StringArrayVar(&commands, "command", nil, `command a Basic secret may be used with, e.g. "gh *" (repeatable; default: any)`)
	f.StringSliceVar(&allowIn, "allow-in", nil, "parts of a request a Scoped secret may go in: header, url, body (default: header only)")
	f.BoolVar(&update, "update", false, "replace an existing secret")
	return cmd
}

func (a *app) askTier() (secret.Tier, error) {
	a.ui.println("How should agents be able to use it?")
	a.ui.printf("  1  %s  in commands, as an environment variable\n", a.ui.bold("Basic  "))
	a.ui.printf("  2  %s  only in requests to hosts you allow %s\n", a.ui.bold("Scoped "), a.ui.dim("(recommended)"))
	a.ui.printf("  3  %s  like Scoped, and you approve each use\n", a.ui.bold("Guarded"))
	for {
		ans, err := a.ui.ask("Choose 1-3:", "2")
		if err != nil {
			return "", err
		}
		switch strings.ToLower(ans) {
		case "1", "basic":
			return secret.Basic, nil
		case "2", "scoped":
			return secret.Scoped, nil
		case "3", "guarded":
			return secret.Guarded, nil
		}
		a.ui.warn("Type 1, 2 or 3.")
	}
}

func (a *app) askDomains(name string) ([]string, error) {
	suggestion := policy.SuggestHost(name)
	for {
		ans, err := a.ui.ask("Which hosts may receive it? (comma-separated)", suggestion)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, d := range strings.Split(ans, ",") {
			if d = strings.TrimSpace(d); d != "" {
				out = append(out, d)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
		a.ui.warn("Add at least one host, like api.example.com.")
	}
}

func (a *app) readValue(name string) (secret.Value, error) {
	var raw []byte
	var err error
	if a.ui.tty && a.env.ReadPwd != nil {
		fmt.Fprintf(a.env.Stderr, "Paste the value for %s %s ", a.ui.bold(name), a.ui.dim("(hidden)"))
		raw, err = a.env.ReadPwd()
		fmt.Fprintln(a.env.Stderr)
	} else {
		raw, err = io.ReadAll(io.LimitReader(a.env.Stdin, 64<<10))
	}
	if err != nil {
		return secret.Value{}, fmt.Errorf("read value: %w", err)
	}
	v := strings.TrimRight(string(raw), "\r\n")
	clear(raw)
	if v == "" {
		return secret.Value{}, errors.New("no value given. Paste it at the prompt, or pipe it in: pbpaste | veil add " + name)
	}
	return secret.NewValue(v), nil
}

func (a *app) listCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "Show your secrets (never their values)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			infos, err := a.broker.List()
			if err != nil {
				return err
			}
			if asJSON {
				if infos == nil {
					infos = []broker.Info{}
				}
				enc := json.NewEncoder(a.env.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(infos)
			}
			if len(infos) == 0 {
				a.ui.println("No secrets yet. Add one with:  " + a.ui.bold("veil add NAME"))
				return nil
			}
			tw := tabwriter.NewWriter(a.env.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, a.ui.dim("NAME")+"\t"+a.ui.dim("PROTECTION")+"\t"+a.ui.dim("WHERE IT CAN GO")+"\t"+a.ui.dim("DESCRIPTION"))
			for _, s := range infos {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.ui.bold(s.Name), a.ui.tierChip(s.Protection), where(s), s.Description)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON for scripts")
	return cmd
}

func where(s broker.Info) string {
	switch {
	case len(s.Hosts) > 0:
		return strings.Join(s.Hosts, ", ")
	case len(s.Commands) > 0:
		return "commands: " + strings.Join(s.Commands, ", ")
	}
	return "any command"
}

func (a *app) rmCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "rm NAME",
		Aliases: []string{"remove", "delete"},
		Short:   "Delete a secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.ToUpper(args[0])
			v, err := a.broker.Vault()
			if err != nil {
				return err
			}
			if _, err := v.Get(name); err != nil {
				return err
			}
			if !yes {
				if !a.ui.tty {
					return fmt.Errorf("deleting %s needs confirmation; add --yes to skip it", name)
				}
				a.ui.warn("Agents that use %s will start failing.", name)
				typed, err := a.ui.ask("Type the name to delete it:", "")
				if err != nil {
					return err
				}
				if typed != name {
					a.ui.println("Kept " + name + ".")
					return nil
				}
			}
			if err := v.Remove(name); err != nil {
				return err
			}
			a.broker.Record(audit.Event{Agent: audit.You, Action: "remove", Secrets: []string{name}, Outcome: audit.Changed})
			a.ui.success("Deleted %s", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return cmd
}

func (a *app) runCmd() *cobra.Command {
	var (
		names   []string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "run --secret NAME [--secret NAME...] -- COMMAND [ARGS...]",
		Short: "Run a command with Basic secrets in its environment",
		Long: `Run a command with secrets as environment variables. The same rules apply
as when an agent asks: only Basic secrets, only allowed commands, and any
secret value in the output is hidden.`,
		Example: `  veil run -s GITHUB_TOKEN -- gh pr list`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, argv []string) error {
			for i := range names {
				names[i] = strings.ToUpper(names[i])
			}
			res, err := a.broker.Run(cmd.Context(), broker.RunRequest{
				Agent: audit.You, Secrets: names, Argv: argv, Timeout: timeout,
			})
			if err != nil {
				return err
			}
			fmt.Fprint(a.env.Stdout, res.Stdout)
			fmt.Fprint(a.env.Stderr, res.Stderr)
			if res.Hidden > 0 {
				a.ui.note("veil: hid %d secret value(s) in the output", res.Hidden)
			}
			if res.Truncated {
				a.ui.note("veil: output was cut off because it was too long")
			}
			if res.TimedOut {
				a.ui.warn("Stopped after %s. Use --timeout to allow longer.", timeout)
			}
			if res.ExitCode != 0 {
				return ExitError{Code: max(res.ExitCode, 1)}
			}
			return nil
		},
	}
	// Everything after the command name belongs to the command, not to veil.
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringArrayVarP(&names, "secret", "s", nil, "secret to put in the environment (repeatable)")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "stop the command after this long (max 10m)")
	return cmd
}

func (a *app) logCmd() *cobra.Command {
	var n int
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show recent secret use",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			events, err := audit.Open(filepath.Join(a.env.Home, "audit.log")).Tail(n)
			if err != nil {
				return err
			}
			if len(events) == 0 {
				a.ui.println("Nothing yet. Every time a secret is used, it shows up here.")
				return nil
			}
			for _, e := range events {
				a.ui.printf("%s  %s  %s\n", a.ui.dim(e.Time.Local().Format("Jan 02 15:04")), a.outcome(e.Outcome), e.Summary())
				if e.Detail != "" && e.Outcome != audit.Used && e.Outcome != audit.Changed {
					a.ui.printf("%s%s\n", strings.Repeat(" ", 25), a.ui.dim(e.Detail))
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&n, "lines", "n", 20, "how many events to show")
	return cmd
}

func (a *app) outcome(o string) string {
	switch o {
	case audit.Used:
		return a.ui.green("used   ")
	case audit.Denied:
		return a.ui.red("blocked")
	case audit.Failed:
		return a.ui.amber("failed ")
	case audit.Changed:
		return a.ui.blue("changed")
	}
	return o
}

func (a *app) mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the MCP server that agents connect to (stdio)",
		Long: `Run Veil as an MCP server over stdin/stdout. Agents start this themselves;
use ` + "`veil connect`" + ` to set that up.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := a.broker.Vault(); err != nil {
				return err
			}
			srv := mcpserver.New(a.broker, a.env.Version)
			err := srv.Run(cmd.Context(), &mcp.StdioTransport{})
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		},
	}
}
