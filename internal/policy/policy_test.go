package policy

import (
	"errors"
	"net/url"
	"testing"

	"github.com/moomdate/veil/internal/secret"
)

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"api.stripe.com":   "api.stripe.com",
		" API.Stripe.COM ": "api.stripe.com",
		"api.stripe.com.":  "api.stripe.com",
		"*.amazonaws.com":  "*.amazonaws.com",
		"localhost":        "localhost",
	}
	for in, want := range good {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*", "*.com", "a.*.com", "https://api.x.com", "api.x.com/v1", "user@api.x.com", "api.x.com:443"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q) should fail", bad)
		}
	}
}

func TestHostAllowed(t *testing.T) {
	pats := []string{"api.stripe.com", "*.amazonaws.com"}
	cases := map[string]bool{
		"api.stripe.com":          true,
		"API.STRIPE.COM":          true,
		"api.stripe.com.":         true,
		"s3.amazonaws.com":        true,
		"a.b.amazonaws.com":       true,
		"amazonaws.com":           false, // wildcard does not match the apex
		"stripe.com":              false,
		"evil-api.stripe.com":     false,
		"api.stripe.com.evil.com": false,
		"evilamazonaws.com":       false,
		"api.stripe.co":           false,
		"":                        false,
	}
	for host, want := range cases {
		if got := HostAllowed(host, pats); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestCheckHTTP(t *testing.T) {
	scoped := secret.Secret{Name: "K", Tier: secret.Scoped, Domains: []string{"api.x.com"}}
	if err := CheckHTTP(scoped, mustURL("https://api.x.com/v1")); err != nil {
		t.Fatalf("allowed request denied: %v", err)
	}
	denied := map[string]struct {
		s secret.Secret
		u string
	}{
		"other host":      {scoped, "https://evil.com/"},
		"plain http":      {scoped, "http://api.x.com/"},
		"userinfo trick":  {scoped, "https://api.x.com@evil.com/"},
		"basic tier":      {secret.Secret{Name: "K", Tier: secret.Basic}, "https://api.x.com/"},
		"guarded for now": {secret.Secret{Name: "K", Tier: secret.Guarded, Domains: []string{"api.x.com"}}, "https://api.x.com/"},
	}
	for name, c := range denied {
		err := CheckHTTP(c.s, mustURL(c.u))
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: err = %v, want ErrDenied", name, err)
		}
	}
	local := secret.Secret{Name: "K", Tier: secret.Scoped, Domains: []string{"127.0.0.1", "localhost"}}
	for _, u := range []string{"http://127.0.0.1:8080/", "http://localhost/"} {
		if err := CheckHTTP(local, mustURL(u)); err != nil {
			t.Errorf("http to loopback %s should be allowed: %v", u, err)
		}
	}
}

func TestCommandMatches(t *testing.T) {
	cases := []struct {
		pat  string
		argv []string
		want bool
	}{
		{"gh *", []string{"gh"}, true},
		{"gh *", []string{"gh", "pr", "create"}, true},
		{"gh *", []string{"ghx", "pr"}, false},
		{"gh *", []string{"/usr/bin/gh"}, false},
		{"npm run migrate", []string{"npm", "run", "migrate"}, true},
		{"npm run migrate", []string{"npm", "run", "migrate", "--", "evil"}, false},
		{"npm run migrate", []string{"npm", "run"}, false},
		{"git push *", []string{"git", "push", "origin", "main"}, true},
		{"git push *", []string{"git", "pull"}, false},
		{"", []string{"anything"}, false},
	}
	for _, c := range cases {
		if got := CommandMatches(c.pat, c.argv); got != c.want {
			t.Errorf("CommandMatches(%q, %q) = %v, want %v", c.pat, c.argv, got, c.want)
		}
	}
}

func TestCheckCommand(t *testing.T) {
	any := secret.Secret{Name: "K", Tier: secret.Basic}
	if err := CheckCommand(any, []string{"env"}); err != nil {
		t.Fatalf("Basic with no command list should allow any command: %v", err)
	}
	gh := secret.Secret{Name: "K", Tier: secret.Basic, Commands: []string{"gh *"}}
	if err := CheckCommand(gh, []string{"gh", "pr", "list"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckCommand(gh, []string{"sh", "-c", "gh pr list"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("shell wrapper should be denied, got %v", err)
	}
	scoped := secret.Secret{Name: "K", Tier: secret.Scoped, Domains: []string{"x.com"}}
	if err := CheckCommand(scoped, []string{"curl"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("Scoped secrets must never go into a command's environment, got %v", err)
	}
}

func TestCheckPlacement(t *testing.T) {
	headerOnly := secret.Secret{Name: "K", Tier: secret.Scoped, Domains: []string{"x.com"}}
	if err := CheckPlacement(headerOnly, secret.InHeader); err != nil {
		t.Fatalf("headers are always allowed by default: %v", err)
	}
	for _, part := range []string{secret.InURL, secret.InBody} {
		if err := CheckPlacement(headerOnly, part); !errors.Is(err, ErrDenied) {
			t.Errorf("%s should be denied by default, got %v", part, err)
		}
	}
	urlOK := headerOnly
	urlOK.AllowIn = []string{secret.InURL}
	if err := CheckPlacement(urlOK, secret.InURL); err != nil {
		t.Fatal(err)
	}
	if err := CheckPlacement(urlOK, secret.InHeader); !errors.Is(err, ErrDenied) {
		t.Fatal("an explicit list replaces the default")
	}
}
