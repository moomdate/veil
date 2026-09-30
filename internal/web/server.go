// Package web serves Veil's local web UI.
//
// Security model (see docs/threat-model.md):
//   - It listens on 127.0.0.1 only and checks the Host header, so other
//     websites can't reach it through DNS rebinding.
//   - The browser gets in with a one-time token from `veil ui`, exchanged
//     for an HttpOnly, SameSite=Strict session cookie. Every POST also needs
//     a CSRF token and a matching Origin.
//   - The token alone never exposes a value or loosens a rule. Revealing a
//     value, or changing where a secret may go, needs the person at the
//     computer to confirm with Touch ID or their password. That check runs
//     in this process through the OS, so a program calling the UI with curl
//     can't pass it.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moomdate/veil/internal/audit"
	"github.com/moomdate/veil/internal/broker"
	"github.com/moomdate/veil/internal/presence"
	"github.com/moomdate/veil/internal/secret"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// IdleTimeout is how long the UI stays open without activity.
const IdleTimeout = 15 * time.Minute

const cookieName = "veil_session"

// Config holds a Server's dependencies.
type Config struct {
	Broker   *broker.Broker
	Audit    *audit.Log
	Presence presence.Checker
	Version  string
	Now      func() time.Time // for tests; defaults to time.Now
}

// Server is one `veil ui` session.
type Server struct {
	cfg   Config
	pages map[string]*template.Template

	mu        sync.Mutex
	addr      string // host:port we listen on, for the Host check
	loginTok  string // one-time; cleared after use
	sessionID string
	csrf      string
	lastSeen  time.Time
	flashMsg  string
	done      chan struct{}

	// import state, kept server-side so values never round-trip through
	// the browser and only the imported file can be deleted
	pendingImport []broker.ImportItem
	pendingFrom   string
	importedFrom  string

	closeOnce sync.Once
}

// New prepares a Server. Call Start to listen.
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pages, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, pages: pages, done: make(chan struct{})}, nil
}

// Start listens on 127.0.0.1:port (0 picks a free port) and returns the URL
// to open, which carries the one-time login token.
func (s *Server) Start(ctx context.Context, port int) (string, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.addr = ln.Addr().String()
	s.loginTok = randomToken()
	s.lastSeen = s.cfg.Now()
	url := "http://" + s.addr + "/login?token=" + s.loginTok
	s.mu.Unlock()

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { //nolint:gosec // shutdown must outlive ctx, which is already done here
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go s.watchIdle(ctx)
	go func() { _ = srv.Serve(ln) }()
	return url, nil
}

// Done is closed when the session ends (locked or idle).
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) close() { s.closeOnce.Do(func() { close(s.done) }) }

func (s *Server) watchIdle(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			s.mu.Lock()
			idle := s.cfg.Now().Sub(s.lastSeen)
			s.mu.Unlock()
			if idle > IdleTimeout {
				s.close()
				return
			}
		}
	}
}

// Handler returns the HTTP handler with all security checks applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.login)

	authed := http.NewServeMux()
	authed.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/secrets", http.StatusSeeOther) })
	authed.HandleFunc("GET /secrets", s.secretsPage)
	authed.HandleFunc("GET /secrets/new", s.secretsPage)
	authed.HandleFunc("POST /secrets", s.createSecret)
	authed.HandleFunc("GET /secrets/{name}", s.secretsPage)
	authed.HandleFunc("GET /secrets/{name}/edit", s.secretsPage)
	authed.HandleFunc("POST /secrets/{name}/reveal", s.revealSecret)
	authed.HandleFunc("POST /secrets/{name}/value", s.replaceValue)
	authed.HandleFunc("POST /secrets/{name}/rules", s.updateRules)
	authed.HandleFunc("POST /secrets/{name}/delete", s.deleteSecret)
	authed.HandleFunc("GET /import", s.importPage)
	authed.HandleFunc("POST /import/preview", s.importPreview)
	authed.HandleFunc("POST /import", s.importRun)
	authed.HandleFunc("POST /import/delete-file", s.importDeleteFile)
	authed.HandleFunc("GET /activity", s.activityPage)
	authed.HandleFunc("GET /agents", s.agentsPage)
	authed.HandleFunc("POST /lock", s.lock)
	mux.Handle("/", s.requireSession(validName(authed)))

	return s.securityHeaders(s.checkHost(mux))
}

// validName turns away any {name} that isn't a valid secret name before a
// handler sees it.
func validName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/secrets/") {
			name := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/secrets/"), "/", 2)[0]
			if name != "new" && secret.ValidateName(name) != nil {
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// checkHost rejects requests whose Host isn't this server, which blocks DNS
// rebinding (a website pointing its own name at 127.0.0.1).
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		addr := s.addr
		s.mu.Unlock()
		_, port, _ := net.SplitHostPort(addr)
		if r.Host != addr && r.Host != "localhost:"+port {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// login trades the one-time token for a session cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	tok := s.loginTok
	ok := tok != "" && subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(tok)) == 1
	if ok {
		s.loginTok = ""
		s.sessionID = randomToken()
		s.csrf = randomToken()
		s.lastSeen = s.cfg.Now()
	}
	sid := s.sessionID
	s.mu.Unlock()

	if !ok {
		s.renderStatus(w, http.StatusForbidden, "This link has expired", "Each link from `veil ui` works once. Run `veil ui` again in your terminal to get a new one.")
		return
	}
	// No Secure flag: the UI is plain http on 127.0.0.1, and Safari drops
	// Secure cookies there. HttpOnly + SameSite=Strict + the Host check
	// keep it away from scripts and other sites.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name: cookieName, Value: sid, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		s.mu.Lock()
		sid, csrf := s.sessionID, s.csrf
		s.mu.Unlock()
		if err != nil || sid == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(sid)) != 1 {
			s.renderStatus(w, http.StatusUnauthorized, "Veil is locked", "Run `veil ui` in your terminal to open it.")
			return
		}
		if r.Method == http.MethodPost {
			if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			got := r.Header.Get("X-CSRF-Token")
			if got == "" {
				got = r.PostFormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(csrf)) != 1 {
				http.Error(w, "missing or wrong CSRF token; reload the page", http.StatusForbidden)
				return
			}
		}
		s.mu.Lock()
		s.lastSeen = s.cfg.Now()
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) lock(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.sessionID, s.csrf = "", ""
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode}) //nolint:gosec // clears the cookie
	s.renderStatus(w, http.StatusOK, "Locked", "Veil's web page is closed. Run `veil ui` to open it again.")
	go func() {
		time.Sleep(200 * time.Millisecond) // let the response reach the browser
		s.close()
	}()
}

func (s *Server) csrfToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.csrf
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(errors.New("crypto/rand failed")) // unrecoverable on any supported OS
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
