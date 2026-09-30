package keystore

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewKey(t *testing.T) {
	a, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewKey()
	if len(a) != KeySize || bytes.Equal(a, b) {
		t.Fatal("keys must be KeySize random bytes")
	}
}

func TestMemory(t *testing.T) {
	var m Memory
	if _, err := m.Load(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: err = %v", err)
	}
	key, _ := NewKey()
	_ = m.Save(key)
	got, _ := m.Load()
	got[0] ^= 0xff // callers must not be able to change the stored key
	again, _ := m.Load()
	if !bytes.Equal(again, key) {
		t.Fatal("Load must return a copy")
	}
	_ = m.Delete()
	if _, err := m.Load(); !errors.Is(err, ErrNotFound) {
		t.Fatal("key still present after Delete")
	}
}
