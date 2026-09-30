package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/moomdate/veil/internal/keystore"
	"github.com/moomdate/veil/internal/secret"
)

const canary = "canary-value-7f3e1b2d"

func newVault(t *testing.T) (*Vault, string, []byte) {
	t.Helper()
	key, err := keystore.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sub", "vault.json")
	v, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	return v, path, key
}

func sample(name string) secret.Secret {
	return secret.Secret{
		Name: name, Value: secret.NewValue(canary), Description: "test",
		Tier: secret.Scoped, Domains: []string{"api.example.com"},
	}
}

func TestRoundTrip(t *testing.T) {
	v, path, key := newVault(t)
	if err := v.Add(sample("API_KEY")); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v2.Get("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value.Reveal() != canary || got.Description != "test" || got.Domains[0] != "api.example.com" {
		t.Fatalf("round trip changed the secret: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatal("timestamps not set")
	}
}

func TestFileHoldsNoPlaintext(t *testing.T) {
	v, path, _ := newVault(t)
	if err := v.Add(sample("API_KEY")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{canary, "API_KEY", "api.example.com"} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("vault file contains %q in plaintext", s)
		}
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	_, path, _ := newVault(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("vault mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("vault dir mode = %v, want 0700", di.Mode().Perm())
	}
}

func TestWrongKey(t *testing.T) {
	_, path, _ := newVault(t)
	other, _ := keystore.NewKey()
	if _, err := Open(path, other); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	v, path, key := newVault(t)
	if err := v.Add(sample("API_KEY")); err != nil {
		t.Fatal(err)
	}
	var env envelope
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	for i := range env.Ciphertext {
		env.Ciphertext[i] ^= 0x01
		data, _ := json.Marshal(env)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, key); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipping byte %d: err = %v, want ErrDecrypt", i, err)
		}
		env.Ciphertext[i] ^= 0x01
	}
}

func TestVersionIsAuthenticated(t *testing.T) {
	_, path, key := newVault(t)
	var env envelope
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &env)
	env.Version = 2
	data, _ = json.Marshal(env)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := Open(path, key); err == nil {
		t.Fatal("opening a vault with a changed version should fail")
	}
}

func TestNotInitialized(t *testing.T) {
	key, _ := keystore.NewKey()
	if _, err := Open(filepath.Join(t.TempDir(), "nope.json"), key); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("err = %v, want ErrNotInitialized", err)
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	_, path, key := newVault(t)
	if _, err := Create(path, key); err == nil {
		t.Fatal("Create should not overwrite an existing vault")
	}
}

func TestAddUpdateRemove(t *testing.T) {
	v, path, key := newVault(t)
	if err := v.Add(sample("B_KEY")); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(sample("A_KEY")); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(sample("A_KEY")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate add: err = %v, want ErrExists", err)
	}
	if list := v.List(); list[0].Name != "A_KEY" || list[1].Name != "B_KEY" {
		t.Fatalf("List not sorted: %v", []string{list[0].Name, list[1].Name})
	}

	before, _ := v.Get("A_KEY")
	upd := sample("A_KEY")
	upd.Value = secret.NewValue("rotated-value-123")
	if err := v.Update(upd); err != nil {
		t.Fatal(err)
	}
	after, _ := v.Get("A_KEY")
	if after.Value.Reveal() != "rotated-value-123" || !after.CreatedAt.Equal(before.CreatedAt) {
		t.Fatal("Update should change the value and keep CreatedAt")
	}
	if err := v.Update(sample("MISSING")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: err = %v", err)
	}

	if err := v.Remove("B_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("B_KEY"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove twice: err = %v", err)
	}
	v2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.List()) != 1 {
		t.Fatalf("after remove, reopened vault has %d secrets, want 1", len(v2.List()))
	}
}

func TestAddValidates(t *testing.T) {
	v, _, _ := newVault(t)
	bad := sample("lower")
	if err := v.Add(bad); err == nil {
		t.Fatal("invalid name should be rejected")
	}
}

func TestNoTempFilesLeft(t *testing.T) {
	v, path, _ := newVault(t)
	for i := range 5 {
		_ = v.Add(sample("K" + string(rune('A'+i))))
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("expected only the vault file, found %d entries", len(entries))
	}
}
