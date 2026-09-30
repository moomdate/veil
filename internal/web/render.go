package web

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"

	"github.com/moomdate/veil/internal/vault"
)

var pageNames = []string{"secrets", "activity", "agents", "import"}

func parseTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"join": strings.Join,
		"has":  func(list []string, s string) bool { return slices.Contains(list, s) },
	}
	base, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/status.html")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{"status": base}
	for _, name := range pageNames {
		t, err := template.Must(base.Clone()).ParseFS(templateFS, "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		pages[name] = t
	}
	return pages, nil
}

type layoutData struct {
	Title       string
	Nav         string
	CSRF        string
	Flash       string
	Error       string
	IdleSeconds int
	Version     string
	Data        any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page, title string, data any) {
	s.renderWith(w, status, page, layoutData{Title: title, Nav: page, Flash: s.takeFlash(), Data: data})
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, page, title string, data any, err error) {
	s.renderWith(w, http.StatusBadRequest, page, layoutData{Title: title, Nav: page, Error: sentence(err.Error()), Data: data})
}

func (s *Server) renderWith(w http.ResponseWriter, status int, page string, d layoutData) {
	d.CSRF = s.csrfToken()
	d.IdleSeconds = int(IdleTimeout.Seconds())
	d.Version = s.cfg.Version
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, "layout.html", d); err != nil {
		http.Error(w, "page failed to render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderStatus shows a full-page message such as "Locked".
func (s *Server) renderStatus(w http.ResponseWriter, status int, heading, body string) {
	var buf bytes.Buffer
	_ = s.pages["status"].ExecuteTemplate(&buf, "status.html", map[string]string{"Heading": heading, "Body": body})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, vault.ErrNotInitialized) {
		s.renderStatus(w, http.StatusOK, "No vault yet", "Run `veil init` in your terminal, then `veil ui` again.")
		return
	}
	s.renderStatus(w, http.StatusInternalServerError, "Something went wrong", sentence(err.Error()))
}

func (s *Server) flash(msg string) {
	s.mu.Lock()
	s.flashMsg = msg
	s.mu.Unlock()
}

func (s *Server) takeFlash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.flashMsg
	s.flashMsg = ""
	return m
}

// sentence capitalizes an error message for display.
func sentence(msg string) string {
	if msg == "" {
		return msg
	}
	return strings.ToUpper(msg[:1]) + msg[1:]
}
