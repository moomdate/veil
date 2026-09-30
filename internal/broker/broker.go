// Package broker is the one place where secrets are looked up, checked
// against policy, used, and audited. The CLI and the MCP server both go
// through it, so the rules are the same no matter who asks.
package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/httpinject"
	"github.com/moomdate/veil/internal/keystore"
	"github.com/moomdate/veil/internal/policy"
	"github.com/moomdate/veil/internal/redact"
	"github.com/moomdate/veil/internal/runner"
	"github.com/moomdate/veil/internal/secret"
	"github.com/moomdate/veil/internal/vault"
)

// Broker serves secret operations for one vault.
type Broker struct {
	vaultPath string
	keys      keystore.Store
	audit     *audit.Log
	http      *http.Client

	mu  sync.Mutex
	key []byte // cached after the first successful load
}

// New returns a Broker. httpClient may be nil to use the default client
// (which never follows redirects).
func New(vaultPath string, keys keystore.Store, log *audit.Log, httpClient *http.Client) *Broker {
	if httpClient == nil {
		httpClient = httpinject.NewClient()
	}
	return &Broker{vaultPath: vaultPath, keys: keys, audit: log, http: httpClient}
}

// Init creates the master key and an empty vault. It fails if a vault
// already exists.
func (b *Broker) Init() error {
	key, err := b.keys.Load()
	switch {
	case errors.Is(err, keystore.ErrNotFound):
		if key, err = keystore.NewKey(); err != nil {
			return err
		}
		if err := b.keys.Save(key); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if _, err := vault.Create(b.vaultPath, key); err != nil {
		return err
	}
	b.mu.Lock()
	b.key = key
	b.mu.Unlock()
	return nil
}

// Vault opens the vault. It is re-read on every call so changes made by
// another Veil process (for example the CLI while the MCP server runs) are
// picked up.
func (b *Broker) Vault() (*vault.Vault, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.key == nil {
		key, err := b.keys.Load()
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, vault.ErrNotInitialized
		}
		if err != nil {
			return nil, err
		}
		b.key = key
	}
	return vault.Open(b.vaultPath, b.key)
}

// Info is what an agent may know about a secret.
type Info struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Protection  string   `json:"protection"`
	Hosts       []string `json:"allowed_hosts,omitempty"`
	Commands    []string `json:"allowed_commands,omitempty"`
	AllowIn     []string `json:"allowed_in,omitempty"`
	HowToUse    string   `json:"how_to_use"`
}

// List describes every secret without revealing values.
func (b *Broker) List() ([]Info, error) {
	v, err := b.Vault()
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, s := range v.List() {
		out = append(out, Info{
			Name:        s.Name,
			Description: s.Description,
			Protection:  string(s.Tier),
			Hosts:       s.Domains,
			Commands:    s.Commands,
			AllowIn:     allowIn(s),
			HowToUse:    howToUse(s),
		})
	}
	return out, nil
}

func howToUse(s secret.Secret) string {
	switch s.Tier {
	case secret.Basic:
		return fmt.Sprintf("run_with_secrets with secrets=[%q]; the command sees $%s", s.Name, s.Name)
	case secret.Scoped:
		return fmt.Sprintf("http_request to %s with {{secret:%s}} in the %s", strings.Join(s.Domains, " or "), s.Name, strings.Join(allowIn(s), " or "))
	default:
		return "needs the user's approval, which this version of Veil does not support yet"
	}
}

func allowIn(s secret.Secret) []string {
	if s.Tier == secret.Basic {
		return nil
	}
	if len(s.AllowIn) == 0 {
		return []string{secret.InHeader}
	}
	return s.AllowIn
}

// RunRequest asks to run a command with secrets in its environment.
type RunRequest struct {
	Agent   string
	Secrets []string
	Argv    []string
	Dir     string
	Timeout time.Duration
}

// Run checks policy for every requested secret, then runs the command.
func (b *Broker) Run(ctx context.Context, req RunRequest) (runner.Result, error) {
	v, err := b.Vault()
	if err != nil {
		return runner.Result{}, err
	}
	all := v.List()
	red := redact.New(all)
	ev := audit.Event{Agent: req.Agent, Action: "run", Secrets: req.Secrets, Target: red.String(shellJoin(req.Argv))}

	if len(req.Secrets) == 0 {
		return runner.Result{}, errors.New("name at least one secret to use; call list_secrets to see what's available")
	}
	var use []secret.Secret
	for _, name := range req.Secrets {
		s, err := v.Get(name)
		if err == nil {
			err = policy.CheckCommand(s, req.Argv)
		}
		if err != nil {
			return runner.Result{}, b.refuse(ev, err)
		}
		use = append(use, s)
	}

	res, err := runner.Run(ctx, runner.Request{Argv: req.Argv, Dir: req.Dir, Secrets: use, Timeout: req.Timeout}, red)
	if err != nil {
		ev.Outcome, ev.Detail = audit.Failed, red.String(err.Error())
		b.record(ev)
		return res, err
	}
	ev.Outcome, ev.Hidden = audit.Used, res.Hidden
	ev.Detail = fmt.Sprintf("exit %d", res.ExitCode)
	b.record(ev)
	return res, nil
}

// HTTP checks policy for every placeholder, then sends the request.
func (b *Broker) HTTP(ctx context.Context, agent string, req httpinject.Request) (httpinject.Response, error) {
	v, err := b.Vault()
	if err != nil {
		return httpinject.Response{}, err
	}
	red := redact.New(v.List())
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	ev := audit.Event{
		Agent:   agent,
		Action:  "http",
		Secrets: httpinject.Referenced(req),
		Target:  red.String(method + " " + req.URL),
	}
	resp, err := httpinject.Do(ctx, b.http, req, v.Get, red)
	if err != nil {
		return resp, b.refuse(ev, err)
	}
	ev.Outcome, ev.Hidden = audit.Used, resp.Hidden
	ev.Detail = fmt.Sprintf("status %d", resp.Status)
	b.record(ev)
	return resp, nil
}

// Record logs an administrative change made outside Run and HTTP.
func (b *Broker) Record(ev audit.Event) { b.record(ev) }

// refuse logs a denial or failure and returns err unchanged.
func (b *Broker) refuse(ev audit.Event, err error) error {
	ev.Outcome = audit.Failed
	if errors.Is(err, policy.ErrDenied) {
		ev.Outcome = audit.Denied
	}
	ev.Detail = err.Error()
	b.record(ev)
	return err
}

func (b *Broker) record(ev audit.Event) {
	if b.audit == nil {
		return
	}
	// A failed audit write must not break the agent's work; the error is
	// visible to the user through `veil log` showing a gap.
	_ = b.audit.Append(ev)
}

// shellJoin renders argv for humans, quoting words that need it.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`|&;<>()*?[]{}!#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts[i] = a
	}
	return strings.Join(parts, " ")
}
