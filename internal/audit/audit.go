// Package audit records every use of a secret in an append-only JSON Lines
// file. Entries name secrets but never contain their values.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Outcome of an event.
const (
	Used    = "used"
	Denied  = "denied"
	Failed  = "failed"
	Changed = "changed"
)

// You is the Agent name for actions the user took directly (CLI or web UI).
const You = "you"

// Event is one audit entry.
type Event struct {
	Time    time.Time `json:"time"`
	Agent   string    `json:"agent"`             // You, or the MCP client's name
	Action  string    `json:"action"`            // run, http, add, update, remove, import, reveal
	Secrets []string  `json:"secrets,omitempty"` // names only
	Target  string    `json:"target,omitempty"`  // command line or METHOD URL, already redacted
	Outcome string    `json:"outcome"`
	Hidden  int       `json:"hidden,omitempty"` // occurrences hidden from output
	Detail  string    `json:"detail,omitempty"`
}

// Summary describes the event in one plain sentence.
func (e Event) Summary() string {
	names := strings.Join(e.Secrets, ", ")
	ran, sent := "ran", "sent"
	if e.Outcome == Denied || e.Outcome == Failed {
		ran, sent = "tried to run", "tried to send"
	}
	hidden := ""
	if e.Hidden > 0 {
		hidden = fmt.Sprintf(" (hid %d)", e.Hidden)
	}
	switch e.Action {
	case "run":
		return fmt.Sprintf("%s %s `%s` with %s%s", e.Agent, ran, e.Target, names, hidden)
	case "http":
		return fmt.Sprintf("%s %s %s with %s%s", e.Agent, sent, e.Target, names, hidden)
	case "add":
		return e.Agent + " added " + names
	case "update":
		return e.Agent + " updated " + names
	case "rules":
		return e.Agent + " changed the rules for " + names
	case "remove":
		return e.Agent + " deleted " + names
	case "import":
		return e.Agent + " imported " + names
	case "reveal":
		if e.Outcome == Denied {
			return e.Agent + " tried to reveal " + names
		}
		return e.Agent + " revealed " + names
	}
	return e.Agent + " " + e.Action + " " + names
}

// Log appends events to a file.
type Log struct {
	path string
	mu   sync.Mutex
	now  func() time.Time
}

// Open returns a Log writing to path. The file is created on first write.
func Open(path string) *Log { return &Log{path: path, now: time.Now} }

// Append writes e, filling in the time if unset.
func (l *Log) Append(e Event) error {
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// Tail returns up to n of the most recent events, oldest first.
func (l *Log) Tail(n int) ([]Event, error) {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // skip damaged lines rather than hide the rest
		}
		events = append(events, e)
		if len(events) > n {
			events = events[1:]
		}
	}
	return events, sc.Err()
}
