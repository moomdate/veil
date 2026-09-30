// Package policy decides whether a secret may be used for a given command
// or HTTP destination. It holds no state and never sees secret values.
package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/moomdate/veil/internal/secret"
)

// ErrDenied is wrapped by every refusal, so callers can tell a policy
// decision apart from an operational error.
var ErrDenied = errors.New("not allowed")

func deny(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDenied}, args...)...)
}

// NormalizeDomain lowercases a host pattern and checks its shape.
// Patterns are exact hosts ("api.stripe.com") or one leading wildcard
// label ("*.amazonaws.com", which matches subdomains but not the apex).
func NormalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	host := strings.TrimPrefix(d, "*.")
	switch {
	case host == "":
		return "", errors.New("empty host")
	case strings.Contains(host, "*"):
		return "", fmt.Errorf("invalid host %q: only a leading *. wildcard is supported", d)
	case strings.ContainsAny(host, "/:@ ?#"):
		return "", fmt.Errorf("invalid host %q: give just the host name, like api.example.com", d)
	case d != host && !strings.Contains(host, "."):
		return "", fmt.Errorf("invalid host %q: a wildcard must cover a real domain, like *.example.com", d)
	}
	return d, nil
}

// HostAllowed reports whether host matches one of the patterns.
func HostAllowed(host string, patterns []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range patterns {
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// CheckHTTP decides whether s may be sent to target.
func CheckHTTP(s secret.Secret, target *url.URL) error {
	switch s.Tier {
	case secret.Basic:
		return deny("%s is a Basic secret and can only be used with run_with_secrets; change it to Scoped with allowed hosts to use it in HTTP requests", s.Name)
	case secret.Guarded:
		return deny("%s is Guarded and needs your approval, which arrives in a later version of Veil; for now use a Scoped secret", s.Name)
	}
	if !secureScheme(target) {
		return deny("%s can only be sent over https", s.Name)
	}
	if !HostAllowed(target.Hostname(), s.Domains) {
		return deny("%s can't be sent to %s; allowed hosts: %s", s.Name, target.Hostname(), strings.Join(s.Domains, ", "))
	}
	return nil
}

// CheckPlacement decides whether s may be filled into the given part of an
// HTTP request (header, url or body).
func CheckPlacement(s secret.Secret, part string) error {
	if s.AllowedIn(part) {
		return nil
	}
	return deny("%s can't be put in the request %s because the server could store it where it can be read back; "+
		"put it in a header, or if this API needs it in the %s, the user can allow that with `veil add --update %s --allow-in %s`",
		s.Name, part, part, s.Name, part)
}

// CheckCommand decides whether s may be injected into argv.
func CheckCommand(s secret.Secret, argv []string) error {
	if s.Tier != secret.Basic {
		return deny("%s is %s and can't be put in a command's environment; use http_request with {{secret:%s}} instead", s.Name, s.Tier.Label(), s.Name)
	}
	if len(s.Commands) == 0 {
		return nil
	}
	for _, pat := range s.Commands {
		if CommandMatches(pat, argv) {
			return nil
		}
	}
	return deny("%s can only be used with: %s", s.Name, strings.Join(s.Commands, ", "))
}

// CommandMatches reports whether argv matches a pattern. A pattern is a
// space-separated list of words compared exactly with argv; a final "*"
// matches any remaining arguments (including none).
//
//	"gh *"            matches `gh pr create --fill`
//	"npm run migrate" matches only `npm run migrate`
func CommandMatches(pattern string, argv []string) bool {
	words := strings.Fields(pattern)
	if len(words) == 0 {
		return false
	}
	if words[len(words)-1] == "*" {
		words = words[:len(words)-1]
		if len(argv) < len(words) {
			return false
		}
		argv = argv[:len(words)]
	}
	if len(words) != len(argv) {
		return false
	}
	for i, w := range words {
		if w != argv[i] {
			return false
		}
	}
	return true
}

// secureScheme allows https everywhere and plain http only to this machine.
func secureScheme(u *url.URL) bool {
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
