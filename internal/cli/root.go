// Package cli implements the `veil` command.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/keystore"
	"github.com/moomdate/veil/internal/presence"
	"github.com/moomdate/veil/internal/vault"
)

// Env is everything the CLI needs from the outside world. Tests replace it.
type Env struct {
	Home     string // directory holding vault.json and audit.log
	Keys     keystore.Store
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	IsTTY    bool                   // stdin and stderr are a terminal, so we can prompt
	ReadPwd  func() ([]byte, error) // reads a line without echo
	Exe      string                 // absolute path of the veil binary
	LookPath func(string) (string, error)
	Version  string

	// Hardened reports whether the running binary is protected against code
	// injection; Protect signs a binary so it is; Reexec restarts the
	// current command. See protect.go.
	Hardened func() bool
	Protect  func(exe string) error
	Reexec   func() error
	// KeyAppOnly is true when only Veil itself can read the master key.
	KeyAppOnly bool

	// Presence confirms the user is at the computer (Touch ID) for the web
	// UI; OpenURL opens a link in the browser.
	Presence presence.Checker
	OpenURL  func(url string) error
}

// DefaultHome returns $VEIL_HOME or ~/.veil.
func DefaultHome() (string, error) {
	if h := os.Getenv("VEIL_HOME"); h != "" {
		return filepath.Abs(h)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".veil"), nil
}

// VaultPath is where the vault file lives inside home.
func VaultPath(home string) string { return filepath.Join(home, "vault.json") }

// ExitError carries a process exit code, used by `veil run`.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// New builds the root command.
func New(env Env) *cobra.Command {
	if env.Presence == nil {
		env.Presence = &presence.System{}
	}
	if env.Hardened == nil {
		env.Hardened = func() bool { return true }
	}
	u := newUI(env)
	b := broker.New(VaultPath(env.Home), env.Keys, audit.Open(filepath.Join(env.Home, "audit.log")), nil)
	a := &app{env: env, ui: u, broker: b}

	root := &cobra.Command{
		Use:   "veil",
		Short: "Let AI agents use your secrets without seeing them",
		Long: `Veil keeps your API keys and tokens encrypted on this computer and lets AI
agents use them by name. Agents never receive the values: Veil fills them in
at the last moment and hides them if they show up in output.

Get started:
  veil init                 create your vault
  veil add GITHUB_TOKEN     store a secret
  veil connect claude       let Claude Code use it
  veil ui                   manage everything in your browser`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       env.Version,
		// Every command that can open the vault first makes sure this binary
		// is protected against code injection (see protect.go).
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			switch cmd.Name() {
			case "protect", "help", "completion", "__complete":
				return nil
			}
			return a.ensureProtected()
		},
	}
	root.SetIn(env.Stdin)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	root.AddCommand(
		a.initCmd(),
		a.addCmd(),
		a.listCmd(),
		a.rmCmd(),
		a.runCmd(),
		a.logCmd(),
		a.mcpCmd(),
		a.connectCmd(),
		a.protectCmd(),
		a.uiCmd(),
		a.importCmd(),
	)
	return root
}

type app struct {
	env    Env
	ui     *ui
	broker *broker.Broker
}

// ExecuteContext runs the CLI and returns the process exit code.
func ExecuteContext(ctx context.Context, env Env, args []string) int {
	cmd := New(env)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var exit ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	u := newUI(env)
	fmt.Fprintln(env.Stderr, u.red("Error:"), friendly(err))
	return 1
}

// friendly adds a next step to errors people commonly hit.
func friendly(err error) string {
	switch {
	case errors.Is(err, vault.ErrNotInitialized):
		return "no vault yet. Run `veil init` to create one."
	case errors.Is(err, vault.ErrNotFound):
		return err.Error() + ". Run `veil list` to see your secrets."
	case errors.Is(err, keystore.ErrUnprotected):
		return err.Error()
	case errors.Is(err, keystore.ErrDenied):
		return err.Error()
	case errors.Is(err, vault.ErrExists):
		return err.Error() + ". Use `veil add --update NAME` to replace it."
	}
	return err.Error()
}
