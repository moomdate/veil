package presence

import (
	"errors"
	"testing"
)

func TestFake(t *testing.T) {
	f := &Fake{}
	if err := f.Confirm("reveal X"); err != nil || f.Reasons[0] != "reveal X" {
		t.Fatal("fake should allow and record the reason")
	}
	if err := (&Fake{Deny: true}).Confirm("x"); !errors.Is(err, ErrCanceled) {
		t.Fatal("deny")
	}
	if err := (&Fake{Unavailable: true}).Confirm("x"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable")
	}
}

// Available never shows a prompt, so it's safe to call in tests.
func TestSystemAvailableDoesNotPanic(t *testing.T) {
	_ = (&System{}).Available()
}
