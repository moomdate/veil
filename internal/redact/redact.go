// Package redact hides secret values in text before an agent can see it.
//
// Besides the raw value, it looks for common encodings an agent might
// produce by accident or on purpose: base64 (standard and URL alphabets, at
// every byte alignment so a secret inside a longer base64 blob is found too),
// hex, URL escaping and JSON escaping.
//
// Redaction is a safety net, not a guarantee: a program that deliberately
// transforms a value (reverses it, encrypts it, prints one character per
// line) will get past it. Veil's other layers (tiers, allowed hosts, allowed
// commands) exist for that reason. See docs/threat-model.md.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/moomdate/veil/internal/secret"
)

// minVariantLen is the shortest encoded form worth matching. Shorter
// fragments would hide ordinary text by coincidence.
const minVariantLen = 6

type pattern struct {
	needle []byte
	name   string
}

// Redactor replaces secret values with [HIDDEN:NAME] markers.
type Redactor struct {
	patterns []pattern
	maxLen   int
}

// New builds a Redactor for the given secrets.
func New(secrets []secret.Secret) *Redactor {
	r := &Redactor{}
	seen := map[string]bool{}
	for _, s := range secrets {
		for _, v := range variants(s.Value.Reveal()) {
			if seen[v] {
				continue
			}
			seen[v] = true
			r.patterns = append(r.patterns, pattern{needle: []byte(v), name: s.Name})
			r.maxLen = max(r.maxLen, len(v))
		}
	}
	// Longer needles first, so when two overlap at the same start the
	// marker names the more specific secret.
	slices.SortStableFunc(r.patterns, func(a, b pattern) int { return len(b.needle) - len(a.needle) })
	return r
}

// Marker is the text that replaces a secret named name.
func Marker(name string) string { return "[HIDDEN:" + name + "]" }

// String returns s with every secret hidden.
func (r *Redactor) String(s string) string {
	return string(r.Bytes([]byte(s)))
}

// Bytes returns b with every secret hidden.
func (r *Redactor) Bytes(b []byte) []byte {
	out, _, _ := r.redact(b, len(b))
	return out
}

// Count returns how many secret occurrences s contains.
func (r *Redactor) Count(s string) int {
	return len(r.find([]byte(s)))
}

type span struct {
	start, end int
	name       string
}

// find returns the non-overlapping regions of b that must be hidden,
// sorted by start. Overlapping matches are merged into one region.
func (r *Redactor) find(b []byte) []span {
	var spans []span
	for _, p := range r.patterns {
		for off := 0; off <= len(b)-len(p.needle); {
			i := bytes.Index(b[off:], p.needle)
			if i < 0 {
				break
			}
			start := off + i
			spans = append(spans, span{start, start + len(p.needle), p.name})
			off = start + 1
		}
	}
	if len(spans) == 0 {
		return nil
	}
	slices.SortStableFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return (b.end - b.start) - (a.end - a.start)
	})
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start < last.end {
			last.end = max(last.end, s.end)
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// redact hides secrets in b. It returns the redacted text for b[:cut], cut,
// and how many regions were hidden. cut equals limit unless a hidden region
// crosses it; then cut moves back to that region's start so the whole
// region is handled on a later call, once anything overlapping it has
// arrived too. Pass limit=len(b) to process everything.
func (r *Redactor) redact(b []byte, limit int) ([]byte, int, int) {
	spans := r.find(b)
	cut := limit
	for _, s := range spans {
		if s.start < cut && s.end > cut {
			cut = s.start
			break
		}
	}
	var out bytes.Buffer
	pos, n := 0, 0
	for _, s := range spans {
		if s.start >= cut {
			break
		}
		out.Write(b[pos:s.start])
		out.WriteString(Marker(s.name))
		pos = s.end
		n++
	}
	out.Write(b[pos:cut])
	return out.Bytes(), cut, n
}

// Writer returns a streaming writer that hides secrets before passing data
// to w. It holds back just enough bytes to catch a secret split across
// writes. Call Close to flush the rest.
func (r *Redactor) Writer(w io.Writer) *Writer {
	return &Writer{r: r, w: w}
}

// Writer is a streaming redacting writer. See [Redactor.Writer].
type Writer struct {
	r   *Redactor
	w   io.Writer
	buf []byte

	// Hidden counts the secret occurrences hidden so far.
	Hidden int
}

func (w *Writer) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	hold := max(w.r.maxLen-1, 0)
	if len(w.buf) <= hold {
		return len(p), nil
	}
	out, cut, n := w.r.redact(w.buf, len(w.buf)-hold)
	w.Hidden += n
	if _, err := w.w.Write(out); err != nil {
		return 0, err
	}
	w.buf = append(w.buf[:0], w.buf[cut:]...)
	return len(p), nil
}

// Close flushes buffered data. It does not close the underlying writer.
func (w *Writer) Close() error {
	out, _, n := w.r.redact(w.buf, len(w.buf))
	w.Hidden += n
	w.buf = w.buf[:0]
	_, err := w.w.Write(out)
	return err
}

// variants returns the forms of v to search for.
func variants(v string) []string {
	if v == "" {
		return nil
	}
	out := []string{v}
	add := func(s string) {
		if len(s) >= minVariantLen && s != v {
			out = append(out, s)
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for _, s := range base64Fragments(enc, []byte(v)) {
			add(s)
		}
	}
	h := hex.EncodeToString([]byte(v))
	add(h)
	add(strings.ToUpper(h))
	add(url.QueryEscape(v))
	add(url.PathEscape(v))
	if j, err := json.Marshal(v); err == nil {
		add(string(j[1 : len(j)-1]))
	}
	return out
}

// base64Fragments returns, for each of the three possible byte alignments,
// the part of the base64 encoding that depends only on v. This finds v even
// when it sits in the middle of a larger encoded blob.
func base64Fragments(enc *base64.Encoding, v []byte) []string {
	enc = enc.WithPadding(base64.NoPadding)
	frags := make([]string, 0, 3)
	for k := range 3 {
		buf := make([]byte, k+len(v))
		copy(buf[k:], v)
		full := enc.EncodeToString(buf)
		start := (8*k + 5) / 6 // first char whose bits all come from v
		end := 8 * (k + len(v)) / 6
		if end > start {
			frags = append(frags, full[start:end])
		}
	}
	return frags
}
