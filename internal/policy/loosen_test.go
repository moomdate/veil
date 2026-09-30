package policy

import (
	"testing"

	"github.com/moomdate/veil/internal/secret"
)

func TestLoosens(t *testing.T) {
	base := secret.Secret{Tier: secret.Scoped, Domains: []string{"api.x.com"}}
	gh := secret.Secret{Tier: secret.Basic, Commands: []string{"gh *"}}
	with := func(s secret.Secret, f func(*secret.Secret)) secret.Secret { f(&s); return s }

	cases := []struct {
		name     string
		old, new secret.Secret
		want     bool
	}{
		{"no change", base, base, false},
		{"description only", base, with(base, func(s *secret.Secret) { s.Description = "x" }), false},
		{"scoped to basic", base, with(base, func(s *secret.Secret) { s.Tier = secret.Basic }), true},
		{"scoped to guarded", base, with(base, func(s *secret.Secret) { s.Tier = secret.Guarded }), false},
		{"add host", base, with(base, func(s *secret.Secret) { s.Domains = []string{"api.x.com", "evil.com"} }), true},
		{"remove host", with(base, func(s *secret.Secret) { s.Domains = []string{"a.com", "b.com"} }), with(base, func(s *secret.Secret) { s.Domains = []string{"a.com"} }), false},
		{"allow body", base, with(base, func(s *secret.Secret) { s.AllowIn = []string{"header", "body"} }), true},
		{"header only explicitly", base, with(base, func(s *secret.Secret) { s.AllowIn = []string{"header"} }), false},
		{"drop command list", gh, with(gh, func(s *secret.Secret) { s.Commands = nil }), true},
		{"add command", gh, with(gh, func(s *secret.Secret) { s.Commands = []string{"gh *", "sh *"} }), true},
		{"narrow commands", with(gh, func(s *secret.Secret) { s.Commands = nil }), gh, false},
	}
	for _, c := range cases {
		if got := Loosens(c.old, c.new); got != c.want {
			t.Errorf("%s: Loosens = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSuggestHost(t *testing.T) {
	if SuggestHost("stripe_secret_key") != "api.stripe.com" || SuggestHost("AWS_SECRET") != "*.amazonaws.com" || SuggestHost("MY_THING") != "" {
		t.Fatal("unexpected suggestion")
	}
}
