// Package runner runs a command with secrets in its environment and
// returns its output with those secrets hidden.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/moomdate/veil/internal/redact"
	"github.com/moomdate/veil/internal/secret"
)

// Defaults for [Request] fields left at zero.
const (
	DefaultTimeout   = 2 * time.Minute
	MaxTimeout       = 10 * time.Minute
	DefaultMaxOutput = 256 << 10 // per stream
)

// Request describes one command run.
type Request struct {
	Argv      []string
	Dir       string
	Secrets   []secret.Secret // injected as NAME=value
	Timeout   time.Duration
	MaxOutput int // bytes kept per stream after redaction
}

// Result is what the caller (and the agent) gets back. It never contains a
// secret value in any encoding the redactor knows.
type Result struct {
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Hidden    int    `json:"hidden"`
	Truncated bool   `json:"truncated,omitempty"`
	TimedOut  bool   `json:"timed_out,omitempty"`
}

// Run executes req. red must know every secret in req.Secrets; the caller
// usually builds it from the whole vault.
func Run(ctx context.Context, req Request, red *redact.Redactor) (Result, error) {
	if len(req.Argv) == 0 {
		return Result{}, errors.New("no command given")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	timeout = min(timeout, MaxTimeout)
	maxOut := req.MaxOutput
	if maxOut <= 0 {
		maxOut = DefaultMaxOutput
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Dir = req.Dir
	cmd.Stdin = nil
	cmd.Env = os.Environ()
	for _, s := range req.Secrets {
		cmd.Env = append(cmd.Env, s.Name+"="+s.Value.Reveal())
	}
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second

	var stdout, stderr capped
	stdout.limit, stderr.limit = maxOut, maxOut
	outW, errW := red.Writer(&stdout), red.Writer(&stderr)
	cmd.Stdout, cmd.Stderr = outW, errW

	runErr := cmd.Run()
	_ = outW.Close()
	_ = errW.Close()

	res := Result{
		Stdout:    string(stdout.buf),
		Stderr:    string(stderr.buf),
		Hidden:    outW.Hidden + errW.Hidden,
		Truncated: stdout.dropped || stderr.dropped,
		TimedOut:  errors.Is(ctx.Err(), context.DeadlineExceeded),
		ExitCode:  cmd.ProcessState.ExitCode(),
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil, errors.As(runErr, &exitErr):
		return res, nil
	case res.TimedOut:
		return res, nil
	default:
		// The command could not start. The error text comes from the OS and
		// names the program, never the environment.
		return res, fmt.Errorf("start %s: %w", req.Argv[0], unwrapExec(runErr))
	}
}

func unwrapExec(err error) error {
	var e *exec.Error
	if errors.As(err, &e) {
		return e.Err
	}
	return err
}

// capped keeps the first limit bytes written to it and drops the rest.
type capped struct {
	buf     []byte
	limit   int
	dropped bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	room := c.limit - len(c.buf)
	if room < len(p) {
		c.dropped = true
		p = p[:max(room, 0)]
	}
	c.buf = append(c.buf, p...)
	return n, nil
}

var _ io.Writer = (*capped)(nil)
