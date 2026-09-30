// Command veil lets AI agents use your secrets without seeing them.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/term"

	"github.com/moomdate/veil/internal/cli"
	"github.com/moomdate/veil/internal/keystore"
	"github.com/moomdate/veil/internal/presence"
)

// openURL opens a link in the default browser.
func openURL(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Run()
	case "linux":
		return exec.Command("xdg-open", url).Run()
	}
	return errors.New("don't know how to open a browser here")
}

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	home, err := cli.DefaultHome()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	exe, err := os.Executable()
	if err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
	}
	env := cli.Env{
		Home:     home,
		Keys:     keystore.OS{Service: "veil", Account: cli.VaultPath(home), RequireHardened: true},
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		IsTTY:    term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())),
		ReadPwd:  func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) },
		Exe:      exe,
		LookPath: exec.LookPath,
		Version:  version,

		Hardened:   keystore.Hardened,
		Protect:    cli.Protect,
		Reexec:     func() error { return syscall.Exec(exe, os.Args, os.Environ()) }, //nolint:gosec // restarts this same binary with the same arguments
		KeyAppOnly: keystore.AppOnly,
		Presence:   &presence.System{},
		OpenURL:    openURL,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.ExecuteContext(ctx, env, os.Args[1:])
}
