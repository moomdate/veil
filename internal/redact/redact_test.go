package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/moomdate/veil/internal/secret"
)

func secretsOf(pairs ...string) []secret.Secret {
	var out []secret.Secret
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, secret.Secret{Name: pairs[i], Value: secret.NewValue(pairs[i+1])})
	}
	return out
}

const tok = "ghp_Abc123/+=xyz?&"

func TestHidesEncodings(t *testing.T) {
	r := New(secretsOf("GITHUB_TOKEN", tok))
	b64 := base64.StdEncoding.EncodeToString([]byte(tok))
	cases := map[string]string{
		"raw":          "token is " + tok + " ok",
		"base64":       b64,
		"base64 url":   base64.URLEncoding.EncodeToString([]byte(tok)),
		"base64 raw":   base64.RawStdEncoding.EncodeToString([]byte(tok)),
		"hex":          hex.EncodeToString([]byte(tok)),
		"HEX":          strings.ToUpper(hex.EncodeToString([]byte(tok))),
		"query escape": "?t=" + url.QueryEscape(tok),
		"path escape":  "/x/" + url.PathEscape(tok),
		"json":         mustJSON(tok),
		"basic auth":   base64.StdEncoding.EncodeToString([]byte("user:" + tok)),
		"basic auth 2": base64.StdEncoding.EncodeToString([]byte("u:" + tok)),
		"embedded b64": base64.StdEncoding.EncodeToString([]byte("{\"token\":\"" + tok + "\"}")),
		"repeated":     tok + tok,
		"multiline":    "a\n" + tok + "\nb",
	}
	for name, in := range cases {
		out := r.String(in)
		if strings.Contains(out, tok) || containsLongFragment(out, tok) {
			t.Errorf("%s: value leaked: %q", name, out)
		}
		if !strings.Contains(out, "[HIDDEN:GITHUB_TOKEN]") {
			t.Errorf("%s: no marker in %q", name, out)
		}
	}
}

// containsLongFragment reports whether out still contains a base64 or hex
// encoding of the whole value, which would mean redaction missed it.
func containsLongFragment(out, v string) bool {
	for _, frag := range variants(v) {
		if strings.Contains(out, frag) {
			return true
		}
	}
	return false
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestLeavesOtherTextAlone(t *testing.T) {
	r := New(secretsOf("K", "supersecretvalue"))
	in := "nothing to see here: 12345 supersecret value"
	if out := r.String(in); out != in {
		t.Fatalf("changed unrelated text: %q", out)
	}
}

func TestOverlappingSecrets(t *testing.T) {
	r := New(secretsOf("OUTER", "prefix-INNER-123456-suffix", "INNER", "INNER-123456"))
	out := r.String("x prefix-INNER-123456-suffix y INNER-123456 z")
	if strings.Contains(out, "INNER-123456") || strings.Contains(out, "prefix") {
		t.Fatalf("overlap leaked: %q", out)
	}
	if !strings.Contains(out, "[HIDDEN:OUTER]") || !strings.Contains(out, "[HIDDEN:INNER]") {
		t.Fatalf("markers missing: %q", out)
	}
}

func TestCount(t *testing.T) {
	r := New(secretsOf("K", "abcdef123"))
	if n := r.Count("abcdef123 and abcdef123"); n != 2 {
		t.Fatalf("Count = %d, want 2", n)
	}
}

func TestEmptyRedactorIsIdentity(t *testing.T) {
	r := New(nil)
	var buf bytes.Buffer
	w := r.Writer(&buf)
	_, _ = w.Write([]byte("hello"))
	_ = w.Close()
	if buf.String() != "hello" || r.String("hi") != "hi" {
		t.Fatal("empty redactor should pass text through")
	}
}

// TestWriterEveryChunking feeds the same input split at every possible
// pair of boundaries and checks the streamed output equals batch output.
func TestWriterEveryChunking(t *testing.T) {
	r := New(secretsOf("A", "alpha-secret-1", "B", "bravo-2-secret"))
	in := "start alpha-secret-1 mid " + base64.StdEncoding.EncodeToString([]byte("bravo-2-secret")) + " end alpha-secret-1"
	want := r.String(in)
	for i := 0; i <= len(in); i++ {
		for j := i; j <= len(in); j++ {
			var buf bytes.Buffer
			w := r.Writer(&buf)
			for _, part := range []string{in[:i], in[i:j], in[j:]} {
				if _, err := w.Write([]byte(part)); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if buf.String() != want {
				t.Fatalf("split at %d,%d: got %q want %q", i, j, buf.String(), want)
			}
			if w.Hidden != 3 {
				t.Fatalf("split at %d,%d: Hidden = %d, want 3", i, j, w.Hidden)
			}
		}
	}
}

func TestWriterByteByByte(t *testing.T) {
	r := New(secretsOf("K", "0123456789abcdef"))
	var buf bytes.Buffer
	w := r.Writer(&buf)
	for _, c := range []byte("xx0123456789abcdefyy") {
		_, _ = w.Write([]byte{c})
	}
	_ = w.Close()
	if got := buf.String(); got != "xx[HIDDEN:K]yy" {
		t.Fatalf("got %q", got)
	}
}

func FuzzNeverLeaks(f *testing.F) {
	f.Add("sk_live_abcdef", "before ", " after", 3)
	f.Add("p@ss w0rd!", "", "", 1)
	f.Add("ÄÖÜ-unicode-秘密", "x", "y", 7)
	f.Fuzz(func(t *testing.T, value, before, after string, chunk int) {
		// Skip values that ordinary text could spell out without the
		// secret: ones found in the surrounding text or in the marker.
		if len(value) < secret.MinValueLen || strings.ContainsAny(value, "[]:") ||
			strings.Contains(before+"\x00"+after, value) || strings.Contains("HIDDEN", value) {
			return
		}
		r := New(secretsOf("K", value))
		inputs := []string{
			before + value + after,
			before + base64.StdEncoding.EncodeToString([]byte(before+value+after)) + after,
			before + hex.EncodeToString([]byte(value)) + after,
			before + url.QueryEscape(value) + after,
		}
		for _, in := range inputs {
			out := r.String(in)
			if strings.Contains(out, value) {
				t.Fatalf("leaked %q in %q", value, out)
			}

			// Streaming must match batch for any chunk size.
			size := (chunk%17+17)%17 + 1
			var buf bytes.Buffer
			w := r.Writer(&buf)
			for i := 0; i < len(in); i += size {
				_, _ = w.Write([]byte(in[i:min(i+size, len(in))]))
			}
			_ = w.Close()
			if buf.String() != out {
				t.Fatalf("streaming (chunk %d) = %q, batch = %q", size, buf.String(), out)
			}
		}
	})
}
