// Package vault stores secrets in a single encrypted file.
//
// File format (JSON):
//
//	{"format":"veil-vault","version":1,"nonce":"<base64>","ciphertext":"<base64>"}
//
// The ciphertext is XChaCha20-Poly1305 over the JSON-encoded list of secrets,
// sealed with the master key and with the format and version as associated
// data. Encrypting names, rules and values together means nobody can read
// the value or loosen a secret's rules (for example, add an allowed host) by
// editing the file without the key.
package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/moomdate/veil/internal/secret"
)

const (
	formatName    = "veil-vault"
	formatVersion = 1
	fileMode      = 0o600
	dirMode       = 0o700
)

var (
	// ErrNotInitialized means the vault file does not exist yet.
	ErrNotInitialized = errors.New("vault not initialized; run `veil init` first")
	// ErrNotFound means no secret has the requested name.
	ErrNotFound = errors.New("secret not found")
	// ErrExists means a secret with that name already exists.
	ErrExists = errors.New("secret already exists")
	// ErrDecrypt means the file could not be opened with the key.
	ErrDecrypt = errors.New("vault could not be decrypted: the master key does not match or the file was modified")
)

type envelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// record is the plaintext form of a secret inside the encrypted payload.
// It is the only place a value is serialized.
type record struct {
	secret.Secret
	Value string `json:"value"`
}

// Vault is an open, decrypted vault. It is not safe for concurrent use;
// callers that share a Vault must serialize access.
type Vault struct {
	path    string
	key     []byte
	secrets []secret.Secret
	now     func() time.Time
}

// Create writes a new, empty vault at path. It fails if the file exists.
func Create(path string, key []byte) (*Vault, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("a vault already exists at %s", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	v := &Vault{path: path, key: key, now: time.Now}
	return v, v.save()
}

// Open reads and decrypts the vault at path.
func Open(path string, key []byte) (*Vault, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("read vault: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("vault file is not valid: %w", err)
	}
	if env.Format != formatName {
		return nil, fmt.Errorf("%s is not a Veil vault", path)
	}
	if env.Version != formatVersion {
		return nil, fmt.Errorf("vault format version %d is not supported by this version of Veil; please upgrade", env.Version)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, associatedData(env.Version))
	if err != nil {
		return nil, ErrDecrypt
	}
	var recs []record
	if err := json.Unmarshal(plain, &recs); err != nil {
		return nil, fmt.Errorf("vault contents are not valid: %w", err)
	}
	v := &Vault{path: path, key: key, now: time.Now}
	for _, r := range recs {
		s := r.Secret
		s.Value = secret.NewValue(r.Value)
		v.secrets = append(v.secrets, s)
	}
	return v, nil
}

// List returns all secrets sorted by name.
func (v *Vault) List() []secret.Secret {
	out := slices.Clone(v.secrets)
	slices.SortFunc(out, func(a, b secret.Secret) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Get returns the secret with the given name.
func (v *Vault) Get(name string) (secret.Secret, error) {
	i := v.index(name)
	if i < 0 {
		return secret.Secret{}, fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	return v.secrets[i], nil
}

// Add stores a new secret and saves the vault.
func (v *Vault) Add(s secret.Secret) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if v.index(s.Name) >= 0 {
		return fmt.Errorf("%s: %w", s.Name, ErrExists)
	}
	now := v.now().UTC()
	s.CreatedAt, s.UpdatedAt = now, now
	v.secrets = append(v.secrets, s)
	return v.save()
}

// Update replaces an existing secret's value and rules, keeping CreatedAt.
func (v *Vault) Update(s secret.Secret) error {
	if err := s.Validate(); err != nil {
		return err
	}
	i := v.index(s.Name)
	if i < 0 {
		return fmt.Errorf("%s: %w", s.Name, ErrNotFound)
	}
	s.CreatedAt = v.secrets[i].CreatedAt
	s.UpdatedAt = v.now().UTC()
	v.secrets[i] = s
	return v.save()
}

// Remove deletes a secret and saves the vault.
func (v *Vault) Remove(name string) error {
	i := v.index(name)
	if i < 0 {
		return fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	v.secrets = slices.Delete(v.secrets, i, i+1)
	return v.save()
}

func (v *Vault) index(name string) int {
	return slices.IndexFunc(v.secrets, func(s secret.Secret) bool { return s.Name == name })
}

func (v *Vault) save() error {
	recs := make([]record, len(v.secrets))
	for i, s := range v.secrets {
		recs[i] = record{Secret: s, Value: s.Value.Reveal()}
	}
	plain, err := json.Marshal(recs)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	aead, err := chacha20poly1305.NewX(v.key)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	env := envelope{
		Format:     formatName,
		Version:    formatVersion,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plain, associatedData(formatVersion)),
	}
	clear(plain)
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	return writeAtomic(v.path, data)
}

func associatedData(version int) []byte {
	return fmt.Appendf(nil, "%s:v%d", formatName, version)
}

// writeAtomic writes data to a temporary file in the same directory and
// renames it over path, so a crash never leaves a half-written vault.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write vault: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write vault: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	return nil
}
