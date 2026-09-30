// Package keystore keeps the vault's master key outside the vault file,
// in the operating system's credential store (macOS Keychain, Linux Secret
// Service, Windows Credential Manager).
package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// KeySize is the master key length in bytes.
const KeySize = 32

// ErrNotFound means no master key has been created yet.
var ErrNotFound = errors.New("master key not found")

// ErrDenied means the user or the OS refused access to the key.
var ErrDenied = errors.New("access to the master key was refused")

// Store loads and saves the master key.
type Store interface {
	Load() ([]byte, error)
	Save(key []byte) error
	Delete() error
}

// NewKey returns a fresh random master key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	return k, nil
}

// Memory keeps the key in memory. It is meant for tests.
type Memory struct {
	mu  sync.Mutex
	key []byte
}

func (m *Memory) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return nil, ErrNotFound
	}
	return append([]byte(nil), m.key...), nil
}

func (m *Memory) Save(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key = append([]byte(nil), key...)
	return nil
}

func (m *Memory) Delete() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key = nil
	return nil
}
