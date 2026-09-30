// Package secret defines the core types shared across Veil: a secret's
// metadata, its protection tier, and Value, a wrapper that refuses to be
// printed, logged, or serialized.
package secret

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// Hidden is what a Value prints as anywhere it is formatted or encoded.
const Hidden = "[HIDDEN]"

// Value holds a secret's plaintext. Every formatting and encoding path
// returns [Hidden], so a Value can never leak through fmt, slog, or JSON by
// accident. Call [Value.Reveal] to get the plaintext; keep those call sites
// few and easy to audit.
type Value struct {
	plain string
}

// NewValue wraps plaintext.
func NewValue(plain string) Value { return Value{plain: plain} }

// Reveal returns the plaintext. Only code that injects the secret into a
// process or request, or that encrypts it at rest, should call this.
func (v Value) Reveal() string { return v.plain }

// IsZero reports whether the value is empty.
func (v Value) IsZero() bool { return v.plain == "" }

// Len returns the plaintext length in bytes.
func (v Value) Len() int { return len(v.plain) }

func (Value) String() string               { return Hidden }
func (Value) GoString() string             { return Hidden }
func (Value) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(Hidden)) }
func (Value) LogValue() slog.Value         { return slog.StringValue(Hidden) }
func (Value) MarshalJSON() ([]byte, error) { return json.Marshal(Hidden) }
func (Value) MarshalText() ([]byte, error) { return []byte(Hidden), nil }
func (*Value) UnmarshalJSON([]byte) error  { return errNoUnmarshal }
func (*Value) UnmarshalText([]byte) error  { return errNoUnmarshal }

var errNoUnmarshal = fmt.Errorf("secret.Value cannot be decoded from text; use secret.NewValue")

// Tier is how strictly a secret is protected.
type Tier string

const (
	// Basic secrets can be injected as environment variables into approved
	// commands. Output is scanned and the value is hidden.
	Basic Tier = "basic"
	// Scoped secrets are only sent in HTTP requests to allowed hosts.
	Scoped Tier = "scoped"
	// Guarded secrets are like Scoped and also need the user's approval for
	// each use.
	Guarded Tier = "guarded"
)

// Valid reports whether t is a known tier.
func (t Tier) Valid() bool { return t == Basic || t == Scoped || t == Guarded }

// Label is the name shown to people.
func (t Tier) Label() string {
	switch t {
	case Basic:
		return "Basic"
	case Scoped:
		return "Scoped"
	case Guarded:
		return "Guarded"
	}
	return string(t)
}

// Places in an HTTP request where a Scoped secret may be filled in.
const (
	InHeader = "header"
	InURL    = "url"
	InBody   = "body"
)

// Secret is a stored secret with its usage rules.
type Secret struct {
	Name        string   `json:"name"`
	Value       Value    `json:"-"`
	Description string   `json:"description"`
	Tier        Tier     `json:"tier"`
	Domains     []string `json:"domains,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	// AllowIn lists where in an HTTP request the value may go. Empty means
	// headers only: a value in the URL or body can be stored by the server
	// (for example in a gist or a comment) and read back later.
	AllowIn   []string  `json:"allow_in,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var nameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// ValidateName checks that name can be used as an environment variable and
// in a {{secret:NAME}} placeholder.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: use capital letters, digits and _, starting with a letter (for example STRIPE_SECRET_KEY)", name)
	}
	return nil
}

// MinValueLen is the shortest value Veil accepts. Very short values would
// match too much ordinary output to be hidden reliably.
const MinValueLen = 6

// AllowedIn reports whether the value may be placed in the given request part.
func (s *Secret) AllowedIn(part string) bool {
	if len(s.AllowIn) == 0 {
		return part == InHeader
	}
	for _, p := range s.AllowIn {
		if p == part {
			return true
		}
	}
	return false
}

// Validate checks the secret's fields for consistency.
func (s *Secret) Validate() error {
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if s.Value.Len() < MinValueLen {
		return fmt.Errorf("%s: value is too short; Veil needs at least %d characters to hide it reliably in output", s.Name, MinValueLen)
	}
	if !s.Tier.Valid() {
		return fmt.Errorf("%s: unknown protection %q; choose basic, scoped or guarded", s.Name, s.Tier)
	}
	for _, p := range s.AllowIn {
		if p != InHeader && p != InURL && p != InBody {
			return fmt.Errorf("%s: unknown request part %q; choose header, url or body", s.Name, p)
		}
	}
	if s.Tier != Basic && len(s.Domains) == 0 {
		return fmt.Errorf("%s: %s secrets need at least one allowed host (--domain api.example.com), or use --tier basic", s.Name, s.Tier.Label())
	}
	return nil
}
