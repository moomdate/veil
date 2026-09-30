//go:build unix

package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/moomdate/veil/internal/redact"
	"github.com/moomdate/veil/internal/secret"
)

const canary = "canary-9d1f2e7a"

var tok = secret.Secret{Name: "TOKEN", Value: secret.NewValue(canary), Tier: secret.Basic}

func run(t *testing.T, argv ...string) Result {
	t.Helper()
	res, err := Run(context.Background(), Request{Argv: argv, Secrets: []secret.Secret{tok}}, redact.New([]secret.Secret{tok}))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSecretReachesCommandButNotOutput(t *testing.T) {
	res := run(t, "sh", "-c", `test "$TOKEN" = "`+canary+`" && echo match; echo "$TOKEN"; echo "$TOKEN" >&2; printf %s "$TOKEN" | base64`)
	all := res.Stdout + res.Stderr
	if !strings.Contains(res.Stdout, "match") {
		t.Fatalf("command did not receive the secret: %q", res.Stdout)
	}
	if strings.Contains(all, canary) {
		t.Fatalf("value leaked: %q", all)
	}
	if res.Hidden != 3 {
		t.Errorf("Hidden = %d, want 3 (stdout, stderr, base64)", res.Hidden)
	}
	if !strings.Contains(res.Stdout, "[HIDDEN:TOKEN]") || !strings.Contains(res.Stderr, "[HIDDEN:TOKEN]") {
		t.Errorf("markers missing: %q / %q", res.Stdout, res.Stderr)
	}
}

func TestExitCode(t *testing.T) {
	if res := run(t, "sh", "-c", "exit 7"); res.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", res.ExitCode)
	}
}

func TestTimeoutKillsChildren(t *testing.T) {
	start := time.Now()
	res, err := Run(context.Background(), Request{
		Argv:    []string{"sh", "-c", "sleep 30 & sleep 30; echo never"},
		Timeout: 300 * time.Millisecond,
	}, redact.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Fatal("TimedOut not set")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v; the process group was not killed", time.Since(start))
	}
}

func TestOutputIsCapped(t *testing.T) {
	res, err := Run(context.Background(), Request{
		Argv:      []string{"sh", "-c", "yes | head -c 10000"},
		MaxOutput: 100,
	}, redact.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) != 100 || !res.Truncated {
		t.Fatalf("len = %d truncated = %v", len(res.Stdout), res.Truncated)
	}
}

func TestMissingProgram(t *testing.T) {
	_, err := Run(context.Background(), Request{Argv: []string{"veil-no-such-program-xyz"}}, redact.New(nil))
	if err == nil {
		t.Fatal("expected an error for a missing program")
	}
}

func TestEmptyArgv(t *testing.T) {
	if _, err := Run(context.Background(), Request{}, redact.New(nil)); err == nil {
		t.Fatal("expected an error")
	}
}
