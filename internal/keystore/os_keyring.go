//go:build !darwin || !cgo

package keystore

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

// AppOnly reports whether the stored key can be read only by Veil itself.
// With the generic keyring backend (Linux Secret Service, or macOS without
// cgo), any program running as the same user can read it.
const AppOnly = false

// ErrUnprotected is never returned on this platform; see os_darwin.go.
var ErrUnprotected = errors.New("this copy of Veil isn't protected")

// Hardened reports whether the binary is protected against code injection.
// Only macOS has a per-binary protection Veil relies on, so elsewhere this
// is always true.
func Hardened() bool { return true }

// OS stores the key in the operating system's credential store.
type OS struct {
	Service         string // keychain service name, e.g. "veil"
	Account         string // keychain account, e.g. the vault path
	RequireHardened bool   // ignored on this platform
}

func (s OS) Load() ([]byte, error) {
	enc, err := keyring.Get(s.Service, s.Account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read master key from the system keychain: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(key) != KeySize {
		return nil, errors.New("the master key in the system keychain is damaged")
	}
	return key, nil
}

func (s OS) Save(key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("master key must be %d bytes", KeySize)
	}
	if err := keyring.Set(s.Service, s.Account, base64.StdEncoding.EncodeToString(key)); err != nil {
		return fmt.Errorf("save master key to the system keychain: %w", err)
	}
	return nil
}

func (s OS) Delete() error {
	err := keyring.Delete(s.Service, s.Account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
