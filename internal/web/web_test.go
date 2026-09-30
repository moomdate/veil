package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/keystore"
	"github.com/moomdate/veil/internal/presence"
	"github.com/moomdate/veil/internal/secret"
)

const canary = "canary-web-5e1d9b3f"

type fixture struct {
	t        *testing.T
	base     string
	loginURL string
	client   *http.Client
	presence *presence.Fake
	broker   *broker.Broker
	home     string
	csrf     string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	home := t.TempDir()
	log := audit.Open(filepath.Join(home, "audit.log"))
	b := broker.New(filepath.Join(home, "vault.json"), &keystore.Memory{}, log, nil)
	if err := b.Init(); err != nil {
		t.Fatal(err)
	}
	v, _ := b.Vault()
	if err := v.Add(secret.Secret{Name: "STRIPE_KEY", Value: secret.NewValue(canary), Tier: secret.Scoped, Domains: []string{"api.stripe.com"}, Description: "test key"}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, presence: &presence.Fake{}, broker: b, home: home}
	srv, err := New(Config{Broker: b, Audit: log, Presence: f.presence, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.loginURL, err = srv.Start(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.loginURL)
	f.base = "http://" + u.Host
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}

func (f *fixture) login() {
	f.t.Helper()
	resp := f.do("GET", f.loginURL, nil, nil)
	if resp.StatusCode != http.StatusSeeOther {
		f.t.Fatalf("login: status %d", resp.StatusCode)
	}
	page := f.get("/secrets")
	m := regexp.MustCompile(`name="csrf" content="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		f.t.Fatal("no CSRF token on the page")
	}
	f.csrf = m[1]
}

func (f *fixture) do(method, target string, form url.Values, hdr map[string]string) *http.Response {
	f.t.Helper()
	if !strings.HasPrefix(target, "http") {
		target = f.base + target
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (f *fixture) get(path string) string {
	f.t.Helper()
	resp := f.do("GET", path, nil, nil)
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), canary) {
		f.t.Fatalf("GET %s: page contains the secret value", path)
	}
	return string(b)
}

func (f *fixture) post(path string, form url.Values) *http.Response {
	f.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf", f.csrf)
	return f.do("POST", path, form, nil)
}

func TestSecurityHeaders(t *testing.T) {
	f := setup(t)
	resp := f.do("GET", "/static/app.css", nil, nil)
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("responses must not be cached")
	}
}

func TestWrongHostRefused(t *testing.T) {
	f := setup(t)
	resp := f.do("GET", f.loginURL, nil, map[string]string{"Host": "evil.example:80"})
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d; DNS rebinding must be refused", resp.StatusCode)
	}
}

func TestNeedsSession(t *testing.T) {
	f := setup(t)
	if resp := f.do("GET", "/secrets", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: status %d", resp.StatusCode)
	}
	if resp := f.do("GET", "/login?token=wrong", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong token: status %d", resp.StatusCode)
	}
	f.login()
	// The login link works only once.
	jar, _ := cookiejar.New(nil)
	other := &http.Client{Jar: jar}
	resp, err := other.Get(f.loginURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reused login link: status %d", resp.StatusCode)
	}
}

func TestPostNeedsCSRFAndSameOrigin(t *testing.T) {
	f := setup(t)
	f.login()
	form := url.Values{"confirm": {"STRIPE_KEY"}}
	if resp := f.do("POST", "/secrets/STRIPE_KEY/delete", form, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no CSRF token: status %d", resp.StatusCode)
	}
	form.Set("csrf", f.csrf)
	if resp := f.do("POST", "/secrets/STRIPE_KEY/delete", form, map[string]string{"Origin": "https://evil.example"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin: status %d", resp.StatusCode)
	}
	v, _ := f.broker.Vault()
	if _, err := v.Get("STRIPE_KEY"); err != nil {
		t.Fatal("refused requests must not change anything")
	}
}

func reveal(f *fixture) (int, map[string]string) {
	resp := f.do("POST", "/secrets/STRIPE_KEY/reveal", nil, map[string]string{"X-CSRF-Token": f.csrf})
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestRevealNeedsPresence(t *testing.T) {
	f := setup(t)
	f.login()

	f.presence.Deny = true
	code, body := reveal(f)
	if code != http.StatusForbidden || body["value"] != "" {
		t.Fatalf("denied presence: status %d body %v", code, body)
	}
	f.presence.Deny, f.presence.Unavailable = false, true
	if code, body := reveal(f); code != http.StatusForbidden || body["value"] != "" {
		t.Fatalf("no presence available: status %d body %v", code, body)
	}

	f.presence.Unavailable = false
	code, body = reveal(f)
	if code != http.StatusOK || body["value"] != canary {
		t.Fatalf("confirmed: status %d", code)
	}
	if f.presence.Reasons[len(f.presence.Reasons)-1] != "reveal STRIPE_KEY" {
		t.Fatalf("prompt should name the secret: %v", f.presence.Reasons)
	}

	events, _ := audit.Open(filepath.Join(f.home, "audit.log")).Tail(10)
	var outcomes []string
	for _, e := range events {
		if e.Action == "reveal" {
			outcomes = append(outcomes, e.Outcome)
		}
	}
	if strings.Join(outcomes, ",") != "denied,denied,used" {
		t.Fatalf("reveal audit = %v", outcomes)
	}
}

func TestLooseningRulesNeedsPresence(t *testing.T) {
	f := setup(t)
	f.login()
	loosen := url.Values{"tier": {"scoped"}, "domains": {"api.stripe.com, evil.example"}, "desc": {"test key"}}

	f.presence.Deny = true
	resp := f.post("/secrets/STRIPE_KEY/rules", loosen)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	v, _ := f.broker.Vault()
	s, _ := v.Get("STRIPE_KEY")
	if len(s.Domains) != 1 {
		t.Fatal("rules changed without confirmation")
	}

	// Tightening or describing doesn't prompt.
	f.presence.Reasons = nil
	f.post("/secrets/STRIPE_KEY/rules", url.Values{"tier": {"guarded"}, "domains": {"api.stripe.com"}, "desc": {"new text"}})
	if len(f.presence.Reasons) != 0 {
		t.Fatalf("tightening shouldn't prompt: %v", f.presence.Reasons)
	}
	v, _ = f.broker.Vault()
	s, _ = v.Get("STRIPE_KEY")
	if s.Tier != secret.Guarded || s.Description != "new text" || s.Value.Reveal() != canary {
		t.Fatalf("rules not saved or value lost: %+v", s)
	}

	f.presence.Deny = false
	f.post("/secrets/STRIPE_KEY/rules", loosen)
	v, _ = f.broker.Vault()
	s, _ = v.Get("STRIPE_KEY")
	if len(s.Domains) != 2 || s.Tier != secret.Scoped {
		t.Fatalf("confirmed change not saved: %+v", s)
	}
}

func TestAddAndDelete(t *testing.T) {
	f := setup(t)
	f.login()
	resp := f.post("/secrets", url.Values{"name": {"GITHUB_TOKEN"}, "value": {"ghp_web_value_1"}, "tier": {"basic"}, "commands": {"gh *"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add: status %d", resp.StatusCode)
	}
	page := f.get("/secrets")
	if !strings.Contains(page, "Saved GITHUB_TOKEN") || !strings.Contains(page, "Commands: gh *") || strings.Contains(page, "ghp_web_value_1") {
		t.Fatal("list should confirm the new secret and never show its value")
	}

	resp = f.post("/secrets", url.Values{"name": {"GITHUB_TOKEN"}, "value": {"x-dup-value"}, "tier": {"basic"}})
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "Replace value") {
		t.Fatalf("duplicate add should explain what to do: %d", resp.StatusCode)
	}
	resp = f.post("/secrets", url.Values{"name": {"NEW_KEY"}, "value": {"value-123"}, "tier": {"scoped"}})
	b, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "allowed host") {
		t.Fatalf("scoped without hosts should fail helpfully: %s", b)
	}

	f.post("/secrets/GITHUB_TOKEN/delete", url.Values{"confirm": {"github_token"}})
	v, _ := f.broker.Vault()
	if _, err := v.Get("GITHUB_TOKEN"); err != nil {
		t.Fatal("a wrong confirmation must not delete")
	}
	f.post("/secrets/GITHUB_TOKEN/delete", url.Values{"confirm": {"GITHUB_TOKEN"}})
	v, _ = f.broker.Vault()
	if _, err := v.Get("GITHUB_TOKEN"); err == nil {
		t.Fatal("not deleted")
	}
}

func TestPagesRender(t *testing.T) {
	f := setup(t)
	f.login()
	for path, want := range map[string]string{
		"/secrets":                 "STRIPE_KEY",
		"/secrets/new":             "Add secret",
		"/secrets/STRIPE_KEY":      "What agents see",
		"/secrets/STRIPE_KEY/edit": "Rules for STRIPE_KEY",
		"/activity":                "Activity",
		"/agents":                  "veil connect claude",
		"/import":                  "Import from .env",
	} {
		if page := f.get(path); !strings.Contains(page, want) {
			t.Errorf("%s: missing %q", path, want)
		}
	}
}

func TestImportDeletesOnlyTheImportedFile(t *testing.T) {
	f := setup(t)
	f.login()
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	other := filepath.Join(dir, "keep.txt")
	_ = os.WriteFile(env, []byte("OPENAI_API_KEY=sk-import-12345\nDEBUG=1\nDB_PASSWORD=hunter2hunter2\n"), 0o600)
	_ = os.WriteFile(other, []byte("x"), 0o600)

	resp := f.post("/import/preview", url.Values{"path": {env}})
	b, _ := io.ReadAll(resp.Body)
	page := string(b)
	if strings.Contains(page, "sk-import-12345") || strings.Contains(page, "hunter2") {
		t.Fatal("preview must not show values")
	}
	if !strings.Contains(page, "too short") || !strings.Contains(page, "api.openai.com") {
		t.Fatalf("preview should skip short values and suggest hosts:\n%s", page)
	}
	// Row 0 OPENAI (scoped), row 1 DEBUG (skipped), row 2 DB_PASSWORD (basic).
	resp = f.post("/import", url.Values{
		"include_0": {"on"}, "tier_0": {"scoped"}, "domains_0": {"api.openai.com"},
		"include_2": {"on"}, "tier_2": {"basic"},
	})
	b, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "Imported 2 secret(s)") {
		t.Fatalf("import result:\n%s", b)
	}
	f.post("/import/delete-file", url.Values{"path": {other}}) // a forged path is ignored
	if _, err := os.Stat(env); !os.IsNotExist(err) {
		t.Fatal("the imported .env should be deleted")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("only the imported file may be deleted")
	}
	v, _ := f.broker.Vault()
	s, _ := v.Get("OPENAI_API_KEY")
	if s.Tier != secret.Scoped || s.Domains[0] != "api.openai.com" {
		t.Fatalf("imported secret = %+v", s)
	}
}

func TestLock(t *testing.T) {
	f := setup(t)
	f.login()
	f.post("/lock", nil)
	if resp := f.do("GET", "/secrets", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after lock: status %d", resp.StatusCode)
	}
}

func TestInvalidNamesRejected(t *testing.T) {
	f := setup(t)
	f.login()
	for _, p := range []string{"/secrets/lower", "/secrets/%2F%2Fevil.example/value", "/secrets/..%2F..%2Fetc"} {
		if resp := f.do("GET", p, nil, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, resp.StatusCode)
		}
	}
}
