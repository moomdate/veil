package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const plain = "sk_live_canary_5f2a9c"

func TestValueNeverFormatsPlaintext(t *testing.T) {
	v := NewValue(plain)
	s := Secret{Name: "API_KEY", Value: v}

	outputs := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		outputs["value "+verb] = fmt.Sprintf(verb, v)
		outputs["secret "+verb] = fmt.Sprintf(verb, s)
		outputs["pointer "+verb] = fmt.Sprintf(verb, &s)
	}
	outputs["Sprint"] = fmt.Sprint(v, s)

	j, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	outputs["json value"] = string(j)
	j, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	outputs["json secret"] = string(j)

	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "v", v, "s", s)
	outputs["slog"] = logBuf.String()

	for name, out := range outputs {
		if strings.Contains(out, plain) || strings.Contains(out, fmt.Sprintf("%x", plain)) {
			t.Errorf("%s leaked the plaintext: %s", name, out)
		}
	}
	if v.Reveal() != plain {
		t.Fatal("Reveal must return the plaintext")
	}
}

func TestValueRefusesDecoding(t *testing.T) {
	var s struct{ V Value }
	if err := json.Unmarshal([]byte(`{"V":"x"}`), &s); err == nil {
		t.Fatal("decoding a Value from JSON should fail")
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"A", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "K8S_TOKEN_2"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"", "lower", "1ABC", "_X", "A-B", "A B", "A;rm", strings.Repeat("A", 129)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestSecretValidate(t *testing.T) {
	good := Secret{Name: "K", Value: NewValue("123456"), Tier: Scoped, Domains: []string{"api.x.com"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Secret{
		"short value":      {Name: "K", Value: NewValue("12345"), Tier: Basic},
		"unknown tier":     {Name: "K", Value: NewValue("123456"), Tier: "open"},
		"scoped no hosts":  {Name: "K", Value: NewValue("123456"), Tier: Scoped},
		"guarded no hosts": {Name: "K", Value: NewValue("123456"), Tier: Guarded},
	}
	for name, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
