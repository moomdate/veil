package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/dotenv"
	"github.com/moomdate/veil/internal/secret"
	"github.com/moomdate/veil/internal/web"
)

func (a *app) uiCmd() *cobra.Command {
	var (
		port   int
		noOpen bool
	)
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open Veil in your browser",
		Long: `Open Veil's web page to manage your secrets. It runs only on this computer
(127.0.0.1) and locks itself after 15 minutes without activity.

Showing a value, or letting a secret go somewhere new, asks you to confirm
with Touch ID or your password.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := a.broker.Vault(); err != nil {
				return err
			}
			srv, err := web.New(web.Config{
				Broker:   a.broker,
				Audit:    audit.Open(filepath.Join(a.env.Home, "audit.log")),
				Presence: a.env.Presence,
				Version:  a.env.Version,
			})
			if err != nil {
				return err
			}
			url, err := srv.Start(cmd.Context(), port)
			if err != nil {
				return fmt.Errorf("start the web page: %w", err)
			}
			opened := false
			if !noOpen && a.env.OpenURL != nil {
				opened = a.env.OpenURL(url) == nil
			}
			if opened {
				a.ui.success("Opened Veil in your browser.")
			} else {
				a.ui.println("Open this link in your browser (it works once):")
				a.ui.println("  " + url)
			}
			a.ui.note("Press Ctrl+C to close it. It locks by itself after 15 minutes idle.")
			select {
			case <-srv.Done():
				a.ui.println("Locked.")
			case <-cmd.Context().Done():
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "port to listen on (default: any free port)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "print the link instead of opening the browser")
	return cmd
}

func (a *app) importCmd() *cobra.Command {
	var yes, keep bool
	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Move secrets from a .env file into Veil",
		Long: `Read KEY=value lines from a .env file and store each one in Veil. Secrets
whose name matches a known API (STRIPE_*, OPENAI_*, ...) become Scoped to that
API's host; the rest become Basic. Review them afterwards with ` + "`veil list`" + `.

After importing, Veil offers to delete the file, since the values in it can
still be read by any program.`,
		Example: "  veil import .env",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := filepath.Abs(args[0])
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("couldn't read %s: %w", path, errors.Unwrap(err))
			}
			entries, err := dotenv.Parse(string(data))
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			items, err := a.broker.PlanImport(entries)
			if err != nil {
				return err
			}
			a.printPlan(items)
			if !yes && a.ui.tty {
				ok, err := a.ui.confirm("Import these?", true)
				if err != nil || !ok {
					a.ui.println("Nothing was imported.")
					return err
				}
			}
			added, err := a.broker.Import(items)
			if err != nil {
				return err
			}
			a.ui.success("Imported %d secret(s).", len(added))
			if keep {
				return nil
			}
			del := yes
			if !yes && a.ui.tty {
				del, _ = a.ui.confirm(fmt.Sprintf("Delete %s now that Veil has the values?", path), true)
			}
			if del {
				if err := os.Remove(path); err != nil {
					return err
				}
				a.ui.success("Deleted %s", path)
			} else {
				a.ui.warn("%s still holds the values in plain text.", path)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask; import and delete the file")
	cmd.Flags().BoolVar(&keep, "keep", false, "never delete the file")
	return cmd
}

func (a *app) printPlan(items []broker.ImportItem) {
	for _, it := range items {
		switch {
		case it.Skip != "":
			a.ui.printf("  %s  %s %s\n", a.ui.dim("skip   "), it.Key, a.ui.dim("("+it.Skip+")"))
		case it.Tier == secret.Basic:
			a.ui.printf("  %s  %s %s\n", a.ui.tierChip(string(it.Tier)), a.ui.bold(it.Name), a.ui.dim("any command"))
		default:
			a.ui.printf("  %s  %s %s\n", a.ui.tierChip(string(it.Tier)), a.ui.bold(it.Name), a.ui.dim(strings.Join(it.Domains, ", ")))
		}
	}
}
