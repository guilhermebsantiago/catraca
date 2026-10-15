// Package signal turns events into the values rules read: counters over
// sliding windows, distinct counts and first-seen facts, per account, API
// key, IP and sender domain.
package signal

import (
	"context"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// Set is what rules see. Each map is exposed to CEL under its name:
// event, account, key, ip and domain. Values are int64, float64, bool,
// string or []string. A signal that could not be computed is absent from its
// map, so a rule that reads it fails and its on_error policy applies.
type Set struct {
	Event   map[string]any
	Account map[string]any
	Key     map[string]any
	IP      map[string]any
	Domain  map[string]any
}

// Catalog computes signals.
type Catalog interface {
	// Observe records ev in the counters and returns the signals as of ev,
	// ev included, in one round trip to the store. Counters use ev.Time, so
	// replaying old events in order reproduces the values they had.
	//
	// When the store fails or ctx expires, Observe still returns the
	// signals that need no store (Set.Event at least) together with the
	// error.
	Observe(ctx context.Context, ev event.Event) (Set, error)
	// MarkLeaked records that an API key was found in public, so key.leaked
	// is true for every later event with that key.
	MarkLeaked(ctx context.Context, apiKeyID string) error
	Close() error
}
