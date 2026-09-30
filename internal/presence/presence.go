// Package presence asks the person at the computer to confirm an action,
// with Touch ID or their login password. The check runs in Veil's own
// process through the operating system, so a program that only talks to
// Veil (an agent calling the web UI with curl, for example) can't pass it.
package presence

import (
	"errors"
	"time"
)

// ErrUnavailable means this system has no way to confirm presence.
var ErrUnavailable = errors.New("confirming it's you isn't available on this system, so this action is turned off")

// ErrCanceled means the person declined or the check failed.
var ErrCanceled = errors.New("not confirmed")

// ErrTimedOut means nobody answered the prompt in time.
var ErrTimedOut = errors.New("no answer in time")

// Timeout is how long a prompt waits for an answer before it is dismissed,
// so an unanswered prompt can't block later ones forever.
const Timeout = 60 * time.Second

// Checker confirms that the user is present.
type Checker interface {
	// Available reports whether Confirm can succeed on this system.
	Available() bool
	// Confirm shows the system prompt with reason, e.g. "reveal STRIPE_KEY",
	// and blocks until the person answers.
	Confirm(reason string) error
}

// Fake is a Checker for tests.
type Fake struct {
	Unavailable bool
	Deny        bool
	Reasons     []string
}

func (f *Fake) Available() bool { return !f.Unavailable }

func (f *Fake) Confirm(reason string) error {
	f.Reasons = append(f.Reasons, reason)
	switch {
	case f.Unavailable:
		return ErrUnavailable
	case f.Deny:
		return ErrCanceled
	}
	return nil
}
