package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ui writes human-facing output. Colors are used only on a terminal and
// never when NO_COLOR is set (https://no-color.org).
type ui struct {
	out, err io.Writer
	in       *bufio.Reader
	color    bool
	tty      bool
}

func newUI(env Env) *ui {
	_, noColor := os.LookupEnv("NO_COLOR")
	return &ui{
		out:   env.Stdout,
		err:   env.Stderr,
		in:    bufio.NewReader(env.Stdin),
		color: env.IsTTY && !noColor,
		tty:   env.IsTTY,
	}
}

func (u *ui) paint(code, s string) string {
	if !u.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (u *ui) bold(s string) string  { return u.paint("1", s) }
func (u *ui) dim(s string) string   { return u.paint("2", s) }
func (u *ui) green(s string) string { return u.paint("32", s) }
func (u *ui) amber(s string) string { return u.paint("33", s) }
func (u *ui) red(s string) string   { return u.paint("31", s) }
func (u *ui) blue(s string) string  { return u.paint("34", s) }

func (u *ui) println(a ...any)           { fmt.Fprintln(u.out, a...) }
func (u *ui) printf(f string, a ...any)  { fmt.Fprintf(u.out, f, a...) }
func (u *ui) success(f string, a ...any) { fmt.Fprintln(u.out, u.green("✓"), fmt.Sprintf(f, a...)) }
func (u *ui) note(f string, a ...any)    { fmt.Fprintln(u.err, u.dim(fmt.Sprintf(f, a...))) }
func (u *ui) warn(f string, a ...any)    { fmt.Fprintln(u.err, u.amber("!"), fmt.Sprintf(f, a...)) }

// ask prints a question and returns the trimmed answer, or def if empty.
func (u *ui) ask(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(u.err, "%s %s ", question, u.dim("["+def+"]"))
	} else {
		fmt.Fprintf(u.err, "%s ", question)
	}
	line, err := u.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// confirm asks a yes/no question.
func (u *ui) confirm(question string, def bool) (bool, error) {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	ans, err := u.ask(question, d)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(ans) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	}
	return def, nil
}

func (u *ui) tierChip(t string) string {
	switch t {
	case "basic":
		return u.dim("Basic  ")
	case "scoped":
		return u.blue("Scoped ")
	case "guarded":
		return u.amber("Guarded")
	}
	return t
}
