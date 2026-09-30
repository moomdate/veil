package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/dotenv"
	"github.com/moomdate/veil/internal/policy"
	"github.com/moomdate/veil/internal/presence"
	"github.com/moomdate/veil/internal/secret"
	"github.com/moomdate/veil/internal/vault"
)

// ---------- secrets ----------

type secretRow struct {
	Name        string
	Description string
	Tier        string
	TierLabel   string
	Where       string
	Domains     []string
	Commands    []string
	AllowIn     []string
	LastUsed    string
	LastUsedBy  string
	HowToUse    string
}

// secretForm holds what the person typed, so a form with an error can be
// shown again without losing it. It never holds a value.
type secretForm struct {
	Name      string
	Desc      string
	Tier      string
	Domains   string
	Commands  string
	AllowURL  bool
	AllowBody bool
	Suggest   string
}

type secretsData struct {
	Rows       []secretRow
	Query      string
	Drawer     string // "", "detail", "new", "edit"
	Current    *secretRow
	Form       secretForm
	CanConfirm bool
}

func (s *Server) loadRows() ([]secretRow, *vault.Vault, error) {
	v, err := s.cfg.Broker.Vault()
	if err != nil {
		return nil, nil, err
	}
	last := s.lastUse()
	var rows []secretRow
	for _, sec := range v.List() {
		rows = append(rows, s.row(sec, last))
	}
	return rows, v, nil
}

type use struct {
	at    time.Time
	agent string
}

// lastUse maps secret names to their most recent successful use.
func (s *Server) lastUse() map[string]use {
	out := map[string]use{}
	if s.cfg.Audit == nil {
		return out
	}
	events, _ := s.cfg.Audit.Tail(2000)
	for _, e := range events {
		if e.Outcome != audit.Used || (e.Action != "run" && e.Action != "http") {
			continue
		}
		for _, n := range e.Secrets {
			out[n] = use{e.Time, e.Agent}
		}
	}
	return out
}

func (s *Server) row(sec secret.Secret, last map[string]use) secretRow {
	r := secretRow{
		Name: sec.Name, Description: sec.Description,
		Tier: string(sec.Tier), TierLabel: sec.Tier.Label(),
		Domains: sec.Domains, Commands: sec.Commands,
		LastUsed: "Never",
	}
	switch {
	case len(sec.Domains) > 0:
		r.Where = strings.Join(sec.Domains, ", ")
	case len(sec.Commands) > 0:
		r.Where = "Commands: " + strings.Join(sec.Commands, ", ")
	default:
		r.Where = "Any command"
	}
	if sec.Tier != secret.Basic {
		r.AllowIn = sec.AllowIn
		if len(r.AllowIn) == 0 {
			r.AllowIn = []string{secret.InHeader}
		}
	}
	if u, ok := last[sec.Name]; ok {
		r.LastUsed, r.LastUsedBy = ago(s.cfg.Now(), u.at), u.agent
	}
	switch sec.Tier {
	case secret.Basic:
		cmd := "your-command"
		if len(sec.Commands) > 0 {
			cmd = strings.TrimSuffix(sec.Commands[0], " *")
		}
		r.HowToUse = fmt.Sprintf("veil run -s %s -- %s", sec.Name, cmd)
	default:
		r.HowToUse = fmt.Sprintf(`"Authorization": "Bearer {{secret:%s}}"`, sec.Name)
	}
	return r
}

func (s *Server) secretsPage(w http.ResponseWriter, r *http.Request) {
	rows, v, err := s.loadRows()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := secretsData{Rows: rows, Query: r.URL.Query().Get("q"), CanConfirm: s.cfg.Presence.Available()}
	name := r.PathValue("name")
	switch {
	case r.URL.Path == "/secrets/new":
		d.Drawer = "new"
		d.Form = secretForm{Tier: string(secret.Scoped)}
	case name != "":
		sec, err := v.Get(name)
		if err != nil {
			s.flash("That secret doesn't exist anymore.")
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}
		row := s.row(sec, s.lastUse())
		d.Current = &row
		d.Drawer = "detail"
		if strings.HasSuffix(r.URL.Path, "/edit") {
			d.Drawer = "edit"
			d.Form = formFrom(sec)
		}
	}
	s.render(w, r, http.StatusOK, "secrets", "Secrets", d)
}

func formFrom(sec secret.Secret) secretForm {
	return secretForm{
		Name: sec.Name, Desc: sec.Description, Tier: string(sec.Tier),
		Domains:   strings.Join(sec.Domains, ", "),
		Commands:  strings.Join(sec.Commands, ", "),
		AllowURL:  slices.Contains(sec.AllowIn, secret.InURL),
		AllowBody: slices.Contains(sec.AllowIn, secret.InBody),
	}
}

// readRules parses the rule fields shared by the add and edit forms.
func readRules(r *http.Request) (secretForm, secret.Secret, error) {
	f := secretForm{
		Name:      strings.ToUpper(strings.TrimSpace(r.PostFormValue("name"))),
		Desc:      strings.TrimSpace(r.PostFormValue("desc")),
		Tier:      r.PostFormValue("tier"),
		Domains:   r.PostFormValue("domains"),
		Commands:  r.PostFormValue("commands"),
		AllowURL:  r.PostFormValue("allow_url") != "",
		AllowBody: r.PostFormValue("allow_body") != "",
	}
	sec := secret.Secret{Name: f.Name, Description: f.Desc, Tier: secret.Tier(f.Tier)}
	if sec.Tier != secret.Basic {
		for _, d := range splitList(f.Domains) {
			nd, err := policy.NormalizeDomain(d)
			if err != nil {
				return f, sec, err
			}
			sec.Domains = append(sec.Domains, nd)
		}
		if f.AllowURL || f.AllowBody {
			sec.AllowIn = []string{secret.InHeader}
			if f.AllowURL {
				sec.AllowIn = append(sec.AllowIn, secret.InURL)
			}
			if f.AllowBody {
				sec.AllowIn = append(sec.AllowIn, secret.InBody)
			}
		}
	} else {
		sec.Commands = splitList(f.Commands)
	}
	return f, sec, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request) {
	f, sec, err := readRules(r)
	value := r.PostFormValue("value")
	if err == nil {
		sec.Value = secret.NewValue(strings.TrimRight(value, "\r\n"))
		if value == "" {
			err = errors.New("paste the value you want to store")
		}
	}
	var v *vault.Vault
	if err == nil {
		v, err = s.cfg.Broker.Vault()
	}
	if err == nil {
		err = v.Add(sec)
	}
	if err != nil {
		if errors.Is(err, vault.ErrExists) {
			err = fmt.Errorf("%s already exists. Open it and choose Replace value instead", sec.Name)
		}
		rows, _, _ := s.loadRows()
		f.Suggest = policy.SuggestHost(f.Name)
		s.renderError(w, r, "secrets", "Secrets", secretsData{Rows: rows, Drawer: "new", Form: f}, err)
		return
	}
	s.cfg.Broker.Record(audit.Event{Agent: audit.You, Action: "add", Secrets: []string{sec.Name}, Outcome: audit.Changed})
	s.flash(fmt.Sprintf("Saved %s. Agents can use it now.", sec.Name))
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, err := s.cfg.Broker.Vault()
	var sec secret.Secret
	if err == nil {
		sec, err = v.Get(name)
	}
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "That secret doesn't exist anymore."})
		return
	}
	ev := audit.Event{Agent: audit.You, Action: "reveal", Secrets: []string{name}}
	if err := s.cfg.Presence.Confirm("reveal " + name); err != nil {
		ev.Outcome = audit.Denied
		s.cfg.Broker.Record(ev)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": presenceMessage(err, "reveal it")})
		return
	}
	ev.Outcome = audit.Used
	s.cfg.Broker.Record(ev)
	writeJSON(w, http.StatusOK, map[string]string{"value": sec.Value.Reveal()})
}

func (s *Server) replaceValue(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	value := strings.TrimRight(r.PostFormValue("value"), "\r\n")
	v, err := s.cfg.Broker.Vault()
	var sec secret.Secret
	if err == nil {
		sec, err = v.Get(name)
	}
	if err == nil {
		sec.Value = secret.NewValue(value)
		err = v.Update(sec)
	}
	if err != nil {
		s.flash("Couldn't replace the value: " + err.Error())
		http.Redirect(w, r, secretURL(name), http.StatusSeeOther)
		return
	}
	s.cfg.Broker.Record(audit.Event{Agent: audit.You, Action: "update", Secrets: []string{name}, Outcome: audit.Changed})
	s.flash("Replaced the value of " + name + ".")
	http.Redirect(w, r, secretURL(name), http.StatusSeeOther)
}

func (s *Server) updateRules(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, err := s.cfg.Broker.Vault()
	var old secret.Secret
	if err == nil {
		old, err = v.Get(name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, updated, err := readRules(r)
	f.Name = name
	updated.Name, updated.Value = name, old.Value
	if err == nil && policy.Loosens(old, updated) {
		// Letting a secret go somewhere new needs the person, not just the
		// page: whoever holds the page's link could otherwise redirect it.
		if cerr := s.cfg.Presence.Confirm("let " + name + " be used in more places"); cerr != nil {
			err = errors.New(presenceMessage(cerr, "save these rules"))
		}
	}
	if err == nil {
		err = v.Update(updated)
	}
	if err != nil {
		rows, _, _ := s.loadRows()
		row := s.row(old, s.lastUse())
		s.renderError(w, r, "secrets", "Secrets", secretsData{Rows: rows, Drawer: "edit", Current: &row, Form: f, CanConfirm: s.cfg.Presence.Available()}, err)
		return
	}
	s.cfg.Broker.Record(audit.Event{Agent: audit.You, Action: "rules", Secrets: []string{name}, Outcome: audit.Changed})
	s.flash("Saved the rules for " + name + ".")
	http.Redirect(w, r, secretURL(name), http.StatusSeeOther)
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if r.PostFormValue("confirm") != name {
		s.flash("Type the name exactly to delete it. Nothing was deleted.")
		http.Redirect(w, r, secretURL(name), http.StatusSeeOther)
		return
	}
	v, err := s.cfg.Broker.Vault()
	if err == nil {
		err = v.Remove(name)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.cfg.Broker.Record(audit.Event{Agent: audit.You, Action: "remove", Secrets: []string{name}, Outcome: audit.Changed})
	s.flash("Deleted " + name + ".")
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func presenceMessage(err error, action string) string {
	if errors.Is(err, presence.ErrTimedOut) {
		return "No answer within a minute, so Veil didn't " + action + ". Try again when you're at your Mac."
	}
	if errors.Is(err, presence.ErrUnavailable) {
		return "This computer can't confirm it's you, so the web page can't " + action + ". Use `veil add --update` in your terminal instead."
	}
	return "Not confirmed, so Veil didn't " + action + "."
}

// ---------- import ----------

type importRow struct {
	Index int
	broker.ImportItem
	Domains string
	Length  int
}

type importData struct {
	Path     string
	Pasted   string
	Rows     []importRow
	Added    []string
	FromFile string
	Step     string // "choose", "review", "done"
}

func (s *Server) importPage(w http.ResponseWriter, r *http.Request) {
	path := ""
	if wd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(wd, ".env")); err == nil {
			path = filepath.Join(wd, ".env")
		}
	}
	s.render(w, r, http.StatusOK, "import", "Import", importData{Step: "choose", Path: path})
}

func (s *Server) importPreview(w http.ResponseWriter, r *http.Request) {
	d := importData{Step: "choose", Path: strings.TrimSpace(r.PostFormValue("path")), Pasted: ""}
	src := r.PostFormValue("pasted")
	from := ""
	if strings.TrimSpace(src) == "" {
		if d.Path == "" {
			s.renderError(w, r, "import", "Import", d, errors.New("choose a .env file or paste its contents"))
			return
		}
		abs, _ := filepath.Abs(d.Path)
		data, err := os.ReadFile(abs)
		if err != nil {
			s.renderError(w, r, "import", "Import", d, fmt.Errorf("couldn't read %s: %w", abs, errors.Unwrap(err)))
			return
		}
		src, from = string(data), abs
	}
	entries, err := dotenv.Parse(src)
	var items []broker.ImportItem
	if err == nil {
		items, err = s.cfg.Broker.PlanImport(entries)
	}
	if err == nil && len(items) == 0 {
		err = errors.New("no variables found")
	}
	if err != nil {
		s.renderError(w, r, "import", "Import", d, err)
		return
	}
	s.mu.Lock()
	s.pendingImport, s.pendingFrom = items, from
	s.mu.Unlock()
	d.Step, d.FromFile = "review", from
	for i, it := range items {
		d.Rows = append(d.Rows, importRow{Index: i, ImportItem: it, Domains: strings.Join(it.Domains, ", "), Length: it.Value.Len()})
	}
	s.render(w, r, http.StatusOK, "import", "Import", d)
}

func (s *Server) importRun(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	items, from := slices.Clone(s.pendingImport), s.pendingFrom
	s.mu.Unlock()
	if items == nil {
		http.Redirect(w, r, "/import", http.StatusSeeOther)
		return
	}
	for i := range items {
		idx := strconv.Itoa(i)
		if items[i].Skip != "" {
			continue
		}
		if r.PostFormValue("include_"+idx) == "" {
			items[i].Skip = "not selected"
			continue
		}
		items[i].Tier = secret.Tier(r.PostFormValue("tier_" + idx))
		items[i].Domains = nil
		if items[i].Tier != secret.Basic {
			for _, dm := range splitList(r.PostFormValue("domains_" + idx)) {
				nd, err := policy.NormalizeDomain(dm)
				if err != nil {
					s.flash(items[i].Name + ": " + err.Error())
					http.Redirect(w, r, "/import", http.StatusSeeOther)
					return
				}
				items[i].Domains = append(items[i].Domains, nd)
			}
		}
	}
	added, err := s.cfg.Broker.Import(items)
	if err != nil && len(added) == 0 {
		s.flash("Nothing was imported: " + err.Error())
		http.Redirect(w, r, "/import", http.StatusSeeOther)
		return
	}
	s.mu.Lock()
	s.pendingImport = nil
	s.importedFrom = from
	s.mu.Unlock()
	d := importData{Step: "done", Added: added, FromFile: from}
	if err != nil {
		s.renderError(w, r, "import", "Import", d, fmt.Errorf("stopped early: %w", err))
		return
	}
	s.render(w, r, http.StatusOK, "import", "Import", d)
}

// importDeleteFile deletes the file that was just imported. The path comes
// from the server's own record of the import, never from the request.
func (s *Server) importDeleteFile(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	path := s.importedFrom
	s.importedFrom = ""
	s.mu.Unlock()
	if path == "" {
		http.Redirect(w, r, "/secrets", http.StatusSeeOther)
		return
	}
	if err := os.Remove(path); err != nil {
		s.flash("Couldn't delete " + path + ": " + err.Error())
	} else {
		s.flash("Deleted " + path + ". Your secrets now live only in Veil.")
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// ---------- activity ----------

type eventRow struct {
	Time    string
	Summary string
	Detail  string
	Kind    string // ok, warn, bad, info
	Label   string
}

type activityData struct {
	Events []eventRow
	Filter string
	Total  int
}

func (s *Server) activityPage(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "all"
	}
	events, err := s.cfg.Audit.Tail(500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := activityData{Filter: filter, Total: len(events)}
	now := s.cfg.Now()
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		attention := e.Outcome == audit.Denied || e.Outcome == audit.Failed || e.Hidden > 0
		switch filter {
		case "attention":
			if !attention {
				continue
			}
		case "used", "denied", "changed":
			if e.Outcome != filter {
				continue
			}
		}
		row := eventRow{Time: stamp(now, e.Time), Summary: e.Summary()}
		switch {
		case e.Outcome == audit.Denied:
			row.Kind, row.Label = "bad", "Blocked"
		case e.Outcome == audit.Failed:
			row.Kind, row.Label = "warn", "Failed"
		case e.Hidden > 0:
			row.Kind, row.Label = "warn", "Hidden"
			row.Detail = fmt.Sprintf("The value showed up %d time(s) in the output. The agent saw [HIDDEN:%s] instead.", e.Hidden, strings.Join(e.Secrets, ", "))
		case e.Outcome == audit.Changed:
			row.Kind, row.Label = "info", "Changed"
		default:
			row.Kind, row.Label = "ok", "Used"
		}
		if e.Outcome == audit.Denied || e.Outcome == audit.Failed {
			row.Detail = e.Detail
		}
		d.Events = append(d.Events, row)
	}
	s.render(w, r, http.StatusOK, "activity", "Activity", d)
}

// ---------- agents ----------

type agentRow struct {
	Name     string
	LastSeen string
	Uses     int
	Blocked  int
	Secrets  string
}

type agentsData struct {
	Agents []agentRow
	Exe    string
}

func (s *Server) agentsPage(w http.ResponseWriter, r *http.Request) {
	events, err := s.cfg.Audit.Tail(5000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := s.cfg.Now()
	type agg struct {
		last          time.Time
		uses, blocked int
		secrets       map[string]bool
	}
	byName := map[string]*agg{}
	for _, e := range events {
		if e.Agent == audit.You || (e.Action != "run" && e.Action != "http") {
			continue
		}
		a := byName[e.Agent]
		if a == nil {
			a = &agg{secrets: map[string]bool{}}
			byName[e.Agent] = a
		}
		a.last = e.Time
		if e.Outcome == audit.Denied {
			a.blocked++
		} else if e.Outcome == audit.Used && now.Sub(e.Time) < 30*24*time.Hour {
			a.uses++
			for _, n := range e.Secrets {
				a.secrets[n] = true
			}
		}
	}
	var d agentsData
	for name, a := range byName {
		names := make([]string, 0, len(a.secrets))
		for n := range a.secrets {
			names = append(names, n)
		}
		slices.Sort(names)
		d.Agents = append(d.Agents, agentRow{Name: name, LastSeen: ago(now, a.last), Uses: a.uses, Blocked: a.blocked, Secrets: strings.Join(names, ", ")})
	}
	slices.SortFunc(d.Agents, func(a, b agentRow) int { return strings.Compare(a.Name, b.Name) })
	s.render(w, r, http.StatusOK, "agents", "Agents", d)
}

// ---------- helpers ----------

// secretURL is the page for a secret. Names are validated by withName, so
// escaping is belt and braces.
func secretURL(name string) string { return "/secrets/" + url.PathEscape(name) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	case d < 14*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
	return t.Local().Format("Jan 2")
}

func stamp(now, t time.Time) string {
	lt := t.Local()
	if lt.YearDay() == now.Local().YearDay() && lt.Year() == now.Local().Year() {
		return lt.Format("15:04")
	}
	return lt.Format("Jan 2 15:04")
}
