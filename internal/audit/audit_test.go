package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAppendAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := Open(path)

	if events, err := l.Tail(5); err != nil || len(events) != 0 {
		t.Fatalf("missing log: %v, %v", events, err)
	}
	for i := range 7 {
		if err := l.Append(Event{Agent: "a", Action: "run", Outcome: Used, Hidden: i}); err != nil {
			t.Fatal(err)
		}
	}
	// A damaged line must not hide the ones after it.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("{not json\n")
	f.Close()
	_ = l.Append(Event{Agent: "a", Action: "run", Outcome: Denied})

	events, err := l.Tail(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Hidden != 5 || events[2].Outcome != Denied {
		t.Fatalf("Tail(3) = %+v", events)
	}
	if events[0].Time.IsZero() {
		t.Fatal("time not filled in")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}
