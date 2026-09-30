package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// Protect signs the binary at exe with the hardened runtime (ad hoc, no
// Apple account needed). This stops other programs injecting code into Veil
// to read the master key. It is a no-op outside macOS.
func Protect(exe string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	out, err := exec.Command("/usr/bin/codesign", "--sign", "-", "--force", "--options", "runtime", exe).CombinedOutput()
	if err != nil {
		return fmt.Errorf("veil couldn't protect itself (%s). If it's installed in a folder you don't own, run:\n  sudo codesign --sign - --force --options runtime %s", strings.TrimSpace(string(out)), exe)
	}
	return nil
}

func (a *app) protectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "protect",
		Short: "Protect this copy of Veil against code injection (macOS)",
		Long: `On macOS, sign the veil binary with the hardened runtime so no other program
can inject code into it to read your master key. ` + "`veil init`" + ` does this for you;
run it again after installing Veil with ` + "`go install`" + ` or building it yourself.

The first time the protected binary opens your vault, macOS may ask for your
password. Choose Always Allow only if you just ran a veil command yourself.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.env.Hardened() {
				a.ui.success("This copy of Veil is already protected.")
				return nil
			}
			if err := a.protect(); err != nil {
				return err
			}
			a.ui.success("Protected %s", a.env.Exe)
			return nil
		},
	}
}

func (a *app) protect() error {
	if a.env.Protect == nil {
		return errors.New("protection isn't available on this system")
	}
	return a.env.Protect(a.env.Exe)
}

// ensureProtected makes sure the running binary is hardened before it
// creates or reads the master key. If it had to sign the binary, it
// restarts the command so the new signature takes effect.
func (a *app) ensureProtected() error {
	if a.env.Hardened() {
		return nil
	}
	a.ui.note("Protecting this copy of Veil against code injection. If macOS then asks for your password to let veil use its key, that's expected after installing or updating Veil.")
	if err := a.protect(); err != nil {
		return err
	}
	if a.env.Reexec == nil {
		return errors.New("veil was protected; run the command again")
	}
	return a.env.Reexec()
}
