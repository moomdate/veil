package policy

import (
	"slices"
	"strings"

	"github.com/moomdate/veil/internal/secret"
)

var tierStrength = map[secret.Tier]int{secret.Basic: 0, secret.Scoped: 1, secret.Guarded: 2}

// Loosens reports whether changing a secret's rules from old to updated lets
// it be used in any place it couldn't be before. Such changes need the
// user's confirmation, because an agent that can change rules could
// otherwise send a secret anywhere.
func Loosens(old, updated secret.Secret) bool {
	if tierStrength[updated.Tier] < tierStrength[old.Tier] {
		return true
	}
	for _, d := range updated.Domains {
		if !slices.Contains(old.Domains, d) {
			return true
		}
	}
	// A Basic secret with no command list may be used with any command.
	if updated.Tier == secret.Basic {
		if len(updated.Commands) == 0 && len(old.Commands) > 0 {
			return true
		}
		for _, c := range updated.Commands {
			if len(old.Commands) > 0 && !slices.Contains(old.Commands, c) {
				return true
			}
		}
	}
	for _, part := range []string{secret.InHeader, secret.InURL, secret.InBody} {
		if updated.AllowedIn(part) && !old.AllowedIn(part) {
			return true
		}
	}
	return false
}

// knownHosts maps words often found in secret names to their API host.
var knownHosts = []struct{ word, host string }{
	{"ANTHROPIC", "api.anthropic.com"},
	{"OPENAI", "api.openai.com"},
	{"STRIPE", "api.stripe.com"},
	{"GITHUB", "api.github.com"},
	{"GITLAB", "gitlab.com"},
	{"CLOUDFLARE", "api.cloudflare.com"},
	{"VERCEL", "api.vercel.com"},
	{"SLACK", "slack.com"},
	{"LINEAR", "api.linear.app"},
	{"NOTION", "api.notion.com"},
	{"SENDGRID", "api.sendgrid.com"},
	{"TWILIO", "api.twilio.com"},
	{"AWS", "*.amazonaws.com"},
}

// SuggestHost guesses the API host for a secret from its name, or returns "".
func SuggestHost(name string) string {
	name = strings.ToUpper(name)
	for _, k := range knownHosts {
		if strings.Contains(name, k.word) {
			return k.host
		}
	}
	return ""
}
