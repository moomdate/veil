package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moomdate/veil/internal/keystore"
)

type harness struct {
	t    *testing.T
	home string
	keys *keystore.Memory
}

func newHarness(t *testing.T) *harness {
	t.Setenv("NO_COLOR", "1")
	return &harness{t: t, home: t.TempDir(), keys: &keystore.Memory{}}
}

// run executes veil with args and stdin, as a non-interactive caller.
func (h *harness) run(stdin string, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	env := Env{
		Home: h.home, Keys: h.keys,
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Exe: "/usr/local/bin/veil", Version: "test",
		LookPath: func(string) (string, error) { return "", errors.New("not found") },
	}
	code = ExecuteContext(context.Background(), env, args)
	return code, out.String(), errOut.String()
}

func (h *harness) ok(stdin string, args ...string) string {
	h.t.Helper()
	code, out, errOut := h.run(stdin, args...)
	if code != 0 {
		h.t.Fatalf("veil %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errOut)
	}
	return out + errOut
}

func TestFirstRunFlow(t *testing.T) {
	h := newHarness(t)

	code, _, errOut := h.run("", "list")
	if code == 0 || !strings.Contains(errOut, "veil init") {
		t.Fatalf("before init, errors should point to `veil init`: %q", errOut)
	}

	out := h.ok("", "init")
	if !strings.Contains(out, "Created your vault") || !strings.Contains(out, "veil add") {
		t.Fatalf("init output should confirm and suggest a next step: %q", out)
	}
	if out := h.ok("", "init"); !strings.Contains(out, "already set up") {
		t.Fatalf("second init should be friendly: %q", out)
	}
	if out := h.ok("", "list"); !strings.Contains(out, "No secrets yet") {
		t.Fatalf("empty list should say how to add one: %q", out)
	}
}

func TestAddListRemove(t *testing.T) {
	h := newHarness(t)
	h.ok("", "init")

	h.ok("sk_test_value_123\n", "add", "stripe_secret_key", "--domain", "API.Stripe.com", "-d", "Stripe test key")
	h.ok("ghp_value_abc123\n", "add", "GITHUB_TOKEN", "--tier", "basic", "--command", "gh *")

	out := h.ok("", "list")
	for _, want := range []string{"STRIPE_SECRET_KEY", "api.stripe.com", "Scoped", "GITHUB_TOKEN", "commands: gh *", "Stripe test key"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sk_test_value_123") || strings.Contains(out, "ghp_value_abc123") {
		t.Fatal("list printed a secret value")
	}

	var infos []map[string]any
	if err := json.Unmarshal([]byte(h.ok("", "list", "--json")), &infos); err != nil || len(infos) != 2 {
		t.Fatalf("list --json: %v, %d items", err, len(infos))
	}

	code, _, errOut := h.run("x\n", "add", "GITHUB_TOKEN", "--tier", "basic")
	if code == 0 || !strings.Contains(errOut, "--update") {
		t.Fatalf("adding a duplicate should suggest --update: %q", errOut)
	}
	h.ok("ghp_rotated_456\n", "add", "GITHUB_TOKEN", "--tier", "basic", "--update")

	code, _, errOut = h.run("", "rm", "GITHUB_TOKEN")
	if code == 0 || !strings.Contains(errOut, "--yes") {
		t.Fatalf("non-interactive rm should require --yes: %q", errOut)
	}
	h.ok("", "rm", "GITHUB_TOKEN", "--yes")
	if out := h.ok("", "list"); strings.Contains(out, "GITHUB_TOKEN") {
		t.Fatal("secret still listed after rm")
	}

	log := h.ok("", "log")
	for _, want := range []string{"you added STRIPE_SECRET_KEY", "you updated GITHUB_TOKEN", "you deleted GITHUB_TOKEN"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q:\n%s", want, log)
		}
	}
}

func TestAddRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	h.ok("", "init")
	cases := []struct {
		stdin string
		args  []string
		want  string
	}{
		{"value123\n", []string{"add", "K"}, "allowed host"}, // scoped needs --domain
		{"value123\n", []string{"add", "1BAD", "--tier", "basic"}, "invalid name"},
		{"", []string{"add", "K", "--tier", "basic"}, "no value given"},
		{"abc\n", []string{"add", "K", "--tier", "basic"}, "too short"},
		{"value123\n", []string{"add", "K", "--domain", "https://x.com/v1"}, "just the host"},
		{"value123\n", []string{"add", "K", "--tier", "open"}, "unknown protection"},
	}
	for _, c := range cases {
		code, _, errOut := h.run(c.stdin, c.args...)
		if code == 0 || !strings.Contains(errOut, c.want) {
			t.Errorf("veil %v: exit %d, stderr %q; want an error mentioning %q", c.args, code, errOut, c.want)
		}
	}
}

func TestRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	h := newHarness(t)
	h.ok("", "init")
	h.ok("run-canary-8812\n", "add", "TOKEN", "--tier", "basic")

	code, out, errOut := h.run("", "run", "-s", "token", "sh", "-c", "echo got:$TOKEN; exit 3")
	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (the command's own)", code)
	}
	if strings.Contains(out, "run-canary-8812") || !strings.Contains(out, "got:[HIDDEN:TOKEN]") {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errOut, "hid 1 secret") {
		t.Fatalf("should tell the user something was hidden: %q", errOut)
	}
}

func TestConnect(t *testing.T) {
	h := newHarness(t)
	h.ok("", "init")
	out := h.ok("", "connect", "other")
	if !strings.Contains(out, `"command": "/usr/local/bin/veil"`) || !strings.Contains(out, `"mcp"`) {
		t.Fatalf("connect other should print MCP config: %s", out)
	}
	out = h.ok("", "connect", "claude")
	if !strings.Contains(out, "claude mcp add --scope user veil -- /usr/local/bin/veil mcp") {
		t.Fatalf("without the claude CLI, should print the command to run: %s", out)
	}

	t.Setenv("HOME", t.TempDir())
	home, _ := os.UserHomeDir()
	cursorCfg := filepath.Join(home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cursorCfg), 0o755)
	_ = os.WriteFile(cursorCfg, []byte(`{"mcpServers":{"other":{"command":"x"}}}`), 0o644)
	h.ok("", "connect", "cursor")
	data, _ := os.ReadFile(cursorCfg)
	if !strings.Contains(string(data), `"veil"`) || !strings.Contains(string(data), `"other"`) {
		t.Fatalf("cursor config should keep other servers and add veil: %s", data)
	}
}

func TestProtectsBeforeUsingKey(t *testing.T) {
	h := newHarness(t)
	var out, errOut bytes.Buffer
	hardened, protected, reexeced := false, "", false
	env := Env{
		Home: h.home, Keys: h.keys,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut,
		Exe:      "/opt/veil",
		LookPath: func(string) (string, error) { return "", errors.New("no") },
		Hardened: func() bool { return hardened },
		Protect:  func(exe string) error { protected = exe; return nil },
		Reexec:   func() error { reexeced = true; hardened = true; return nil },
	}
	if code := ExecuteContext(context.Background(), env, []string{"init"}); code != 0 {
		t.Fatalf("init failed: %s", errOut.String())
	}
	if protected != "/opt/veil" || !reexeced {
		t.Fatalf("init should protect the binary and restart: protected=%q reexec=%v", protected, reexeced)
	}

	protected, reexeced = "", false
	if code := ExecuteContext(context.Background(), env, []string{"list"}); code != 0 || protected != "" {
		t.Fatalf("an already protected binary must not be signed again")
	}
	if code := ExecuteContext(context.Background(), env, []string{"protect"}); code != 0 || !strings.Contains(out.String(), "already protected") {
		t.Fatalf("protect on a protected binary should say so: %s", out.String())
	}
}

func TestImport(t *testing.T) {
	h := newHarness(t)
	h.ok("", "init")
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	_ = os.WriteFile(env, []byte("STRIPE_KEY=sk_test_import_1\nexport DB_URL=\"postgres://u:p@h/db\"\nDEBUG=1\n"), 0o600)

	out := h.ok("", "import", env, "--keep")
	for _, want := range []string{"STRIPE_KEY", "api.stripe.com", "DB_URL", "any command", "skip", "too short", "Imported 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("import output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sk_test_import_1") {
		t.Fatal("import printed a value")
	}
	if _, err := os.Stat(env); err != nil {
		t.Fatal("--keep must not delete the file")
	}

	// Everything is already imported now, so a second run has nothing to do.
	if code, _, errOut := h.run("", "import", env, "--yes"); code == 0 || !strings.Contains(errOut, "nothing to import") {
		t.Fatalf("re-import: %d %q", code, errOut)
	}
	_ = os.WriteFile(env, []byte("NEW_TOKEN=abcdef123456\n"), 0o600)
	h.ok("", "import", env, "--yes")
	if _, err := os.Stat(env); !os.IsNotExist(err) {
		t.Fatal("--yes should delete the file after importing")
	}
}
