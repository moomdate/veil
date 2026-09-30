// Package httpinject sends HTTP requests on an agent's behalf, replacing
// {{secret:NAME}} placeholders with real values only after checking that
// each secret may go to the request's host.
package httpinject

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/moomdate/veil/internal/policy"
	"github.com/moomdate/veil/internal/redact"
	"github.com/moomdate/veil/internal/secret"
)

// MaxResponse is how many bytes of a response body are returned.
const MaxResponse = 1 << 20

var placeholderRE = regexp.MustCompile(`\{\{\s*secret:([A-Za-z0-9_]+)\s*\}\}`)

// Request is an HTTP request with {{secret:NAME}} placeholders allowed in
// the URL path and query, header values, and body.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Response is the reply with secrets hidden.
type Response struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Hidden    int               `json:"hidden"`
	Truncated bool              `json:"truncated,omitempty"`
}

// Lookup returns the secret with the given name.
type Lookup func(name string) (secret.Secret, error)

// Referenced returns the secret names used in req, without duplicates.
func Referenced(req Request) []string {
	var names []string
	add := func(s string) {
		for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
			if !slices.Contains(names, m[1]) {
				names = append(names, m[1])
			}
		}
	}
	add(req.URL)
	for k, v := range req.Headers {
		add(k)
		add(v)
	}
	add(req.Body)
	return names
}

// partsUsing returns which parts of req contain a placeholder for name.
func partsUsing(req Request, name string) []string {
	has := func(s string) bool {
		for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
			if m[1] == name {
				return true
			}
		}
		return false
	}
	var parts []string
	for _, v := range req.Headers {
		if has(v) {
			parts = append(parts, secret.InHeader)
			break
		}
	}
	if has(req.URL) {
		parts = append(parts, secret.InURL)
	}
	if has(req.Body) {
		parts = append(parts, secret.InBody)
	}
	return parts
}

// NewClient returns an HTTP client suitable for Do. It never follows
// redirects, so a secret can't be forwarded to a host it isn't allowed on.
func NewClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Do checks, fills in and sends req. red must know every secret that can
// be referenced so it can hide values echoed back by the server.
func Do(ctx context.Context, client *http.Client, req Request, lookup Lookup, red *redact.Redactor) (Response, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	target, err := url.Parse(req.URL)
	if err != nil || target.Host == "" {
		return Response{}, fmt.Errorf("invalid url %q: give a full URL like https://api.example.com/v1/items", req.URL)
	}
	if placeholderRE.MatchString(target.Scheme + "://" + target.Host) {
		return Response{}, errors.New("a secret placeholder can't be used in the URL's host")
	}
	for k := range req.Headers {
		if placeholderRE.MatchString(k) {
			return Response{}, errors.New("a secret placeholder can't be used as a header name; put it in the header value")
		}
		if strings.EqualFold(k, "Host") {
			return Response{}, errors.New("the Host header can't be set; put the host in the URL")
		}
	}

	values := map[string]string{}
	for _, name := range Referenced(req) {
		s, err := lookup(name)
		if err != nil {
			return Response{}, err
		}
		if err := policy.CheckHTTP(s, target); err != nil {
			return Response{}, err
		}
		for _, part := range partsUsing(req, name) {
			if err := policy.CheckPlacement(s, part); err != nil {
				return Response{}, err
			}
		}
		values[name] = s.Value.Reveal()
	}
	fill := func(s string, escape func(string) string) string {
		return placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
			return escape(values[placeholderRE.FindStringSubmatch(m)[1]])
		})
	}
	identity := func(s string) string { return s }

	finalURL, err := url.Parse(fill(req.URL, url.QueryEscape))
	if err != nil || finalURL.Host != target.Host {
		return Response{}, errors.New("the URL changed after filling in secrets; keep placeholders in the path or query")
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, finalURL.String(), strings.NewReader(fill(req.Body, identity)))
	if err != nil {
		return Response{}, fmt.Errorf("build request: %s", red.String(err.Error()))
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, fill(v, identity))
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		// Transport errors can quote the URL, which may now hold a value.
		return Response{}, fmt.Errorf("request failed: %s", red.String(err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return Response{}, fmt.Errorf("read response: %s", red.String(err.Error()))
	}
	out := Response{Status: resp.StatusCode, Headers: map[string]string{}}
	if len(body) > MaxResponse {
		body, out.Truncated = body[:MaxResponse], true
	}
	redacted := red.Bytes(body)
	out.Body = string(redacted)
	out.Hidden = red.Count(string(body))
	for k := range resp.Header {
		v := resp.Header.Get(k)
		out.Hidden += red.Count(v)
		out.Headers[k] = red.String(v)
	}
	return out, nil
}
