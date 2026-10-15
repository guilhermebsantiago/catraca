package rules

import (
	"errors"
	"sync"
	"sync/atomic"
)

// Holder keeps the current ruleset and swaps it atomically on reload, so
// in-flight decisions finish on the ruleset they started with. The zero
// value is ready to use and holds no ruleset.
type Holder struct {
	cur atomic.Pointer[Ruleset]
	// mu serializes Load and Reload so concurrent reloads cannot finish out
	// of order and leave an older file in place.
	mu   sync.Mutex
	path string
}

// NewHolder returns a Holder with rs as its current ruleset.
func NewHolder(rs *Ruleset) *Holder {
	h := &Holder{}
	h.cur.Store(rs)
	return h
}

// Load parses the ruleset at path, makes it current and remembers path for
// Reload. On error the current ruleset and path are unchanged.
func (h *Holder) Load(path string) (*Ruleset, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rs, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	h.path = path
	h.cur.Store(rs)
	return rs, nil
}

// Reload parses the file given to Load again and makes it current. On error,
// such as a typo in an edited file, the current ruleset stays in place.
func (h *Holder) Reload() (*Ruleset, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.path == "" {
		return nil, errors.New("rules: nothing to reload: no ruleset was loaded from a file")
	}
	rs, err := LoadFile(h.path)
	if err != nil {
		return nil, err
	}
	h.cur.Store(rs)
	return rs, nil
}

// Store makes rs current, for rulesets that do not come from a file.
func (h *Holder) Store(rs *Ruleset) {
	h.cur.Store(rs)
}

// Current returns the current ruleset, or nil when none was loaded.
func (h *Holder) Current() *Ruleset {
	return h.cur.Load()
}

// Path returns the file Reload reads, or "" when none was loaded.
func (h *Holder) Path() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.path
}
