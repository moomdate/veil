package broker

import (
	"errors"
	"strings"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/dotenv"
	"github.com/moomdate/veil/internal/policy"
	"github.com/moomdate/veil/internal/secret"
)

// ImportItem is one variable from a .env file and what Veil would do with it.
type ImportItem struct {
	Key     string       // as written in the file
	Name    string       // the secret name Veil will use
	Value   secret.Value `json:"-"`
	Tier    secret.Tier
	Domains []string
	Skip    string // why it won't be imported; empty if it will
}

// PlanImport decides, for each entry, the secret name and protection to
// use, or why it should be skipped. Secrets whose name suggests a known API
// become Scoped to that host; others become Basic.
func (b *Broker) PlanImport(entries []dotenv.Entry) ([]ImportItem, error) {
	v, err := b.Vault()
	if err != nil {
		return nil, err
	}
	items := make([]ImportItem, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		it := ImportItem{Key: e.Key, Name: normalizeName(e.Key), Value: secret.NewValue(e.Value)}
		host := policy.SuggestHost(it.Name)
		if host != "" {
			it.Tier, it.Domains = secret.Scoped, []string{host}
		} else {
			it.Tier = secret.Basic
		}
		switch {
		case secret.ValidateName(it.Name) != nil:
			it.Skip = "the name can't be used as a secret name"
		case e.Value == "":
			it.Skip = "empty"
		case len(e.Value) < secret.MinValueLen:
			it.Skip = "too short to hide reliably"
		case seen[it.Name]:
			it.Skip = "appears twice"
		default:
			if _, err := v.Get(it.Name); err == nil {
				it.Skip = "already in Veil"
			}
		}
		seen[it.Name] = true
		items = append(items, it)
	}
	return items, nil
}

// Import stores every item that isn't skipped and returns the names added.
// It stops at the first error; secrets added before it stay added.
func (b *Broker) Import(items []ImportItem) ([]string, error) {
	v, err := b.Vault()
	if err != nil {
		return nil, err
	}
	var added []string
	for _, it := range items {
		if it.Skip != "" {
			continue
		}
		s := secret.Secret{Name: it.Name, Value: it.Value, Tier: it.Tier, Domains: it.Domains, Description: "Imported from .env"}
		if err := v.Add(s); err != nil {
			return added, err
		}
		added = append(added, it.Name)
	}
	if len(added) > 0 {
		b.Record(audit.Event{Agent: audit.You, Action: "import", Secrets: added, Outcome: audit.Changed})
	}
	if len(added) == 0 {
		return nil, errors.New("nothing to import")
	}
	return added, nil
}

func normalizeName(key string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimSpace(key)))
}
