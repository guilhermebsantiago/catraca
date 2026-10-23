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
// map, so a rule that reads it fails and its on_error policy applies. The
// exception is key.leaked, which the catalog can answer from memory when the
// store fails; see Catalog.Observe.
type Set struct {
	Event   map[string]any
	Account map[string]any
	Key     map[string]any
	IP      map[string]any
	Domain  map[string]any
	// Duplicate is true when the event had counted already: the store
	// remembered its id, and its increments were skipped. It is not a
	// signal rules read.
	Duplicate bool
}

// Catalog computes signals.
type Catalog interface {
	// Observe records ev in the counters and returns the signals as of ev,
	// ev included, in one round trip to the store. Counters use ev.Time, so
	// replaying old events in order reproduces the values they had.
	//
	// An event with an id counts once: observed again with the same type,
	// account and id while the catalog remembers it (Options.DedupeTTL), it
	// increments nothing and Set.Duplicate is true, so a retry, or a request
	// sent again after a timeout, does not inflate the counters. Its signals
	// are read as usual and include the first observation, which also
	// recorded what is seen and first-seen, so new_ip and the like may now be
	// false. An event without an id counts every time.
	//
	// When the store fails or ctx expires, Observe still returns the
	// signals that need no store (Set.Event at least) together with the
	// error. If the catalog knows that ev's API key leaked, because it was
	// marked or reported here or an earlier read saw it leaked, Set.Key then
	// holds leaked = true and nothing else; for any other key Set.Key is
	// nil.
	Observe(ctx context.Context, ev event.Event) (Set, error)
	// MarkLeaked records that an API key was found in public, so key.leaked
	// is true for every later event with that key. The catalog also keeps
	// the key in memory, even when the store write fails, so key.leaked
	// stays true for it in this process while the store is down.
	MarkLeaked(ctx context.Context, apiKeyID string) error
	Close() error
}
