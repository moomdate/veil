//go:build !darwin || !cgo

package presence

// System has no presence check outside macOS yet, so actions that need one
// are turned off rather than allowed.
type System struct{}

func (*System) Available() bool      { return false }
func (*System) Confirm(string) error { return ErrUnavailable }
