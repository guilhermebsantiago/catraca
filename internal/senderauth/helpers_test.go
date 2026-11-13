package senderauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// errServFail stands for a SERVFAIL, a timeout or any other failure that
// is not an answer.
var errServFail = errors.New("server misbehaving")

// fakeDNS is a Resolver over a fixed zone. A name without records is
// NXDOMAIN. No test does real DNS.
type fakeDNS struct {
	mu    sync.Mutex
	txt   map[string][]string
	errs  map[string]error
	calls map[string]int
	// block, when set, makes every lookup wait for it to close or for its
	// context to end.
	block chan struct{}
	// started, when set, receives each name as its lookup starts.
	started chan string
	// onLookup, when set, runs at the start of every lookup.
	onLookup func(name string)
}

func newFakeDNS(zone map[string][]string) *fakeDNS {
	return &fakeDNS{txt: zone, errs: map[string]error{}, calls: map[string]int{}}
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.mu.Lock()
	f.calls[name]++
	txt, hasTXT := f.txt[name]
	err, hasErr := f.errs[name]
	block, started, on := f.block, f.started, f.onLookup
	f.mu.Unlock()
	if on != nil {
		on(name)
	}
	if started != nil {
		started <- name
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	switch {
	case hasErr:
		return nil, err
	case hasTXT:
		return slices.Clone(txt), nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
}

func (f *fakeDNS) callsTo(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeDNS) totalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

// lookupOf returns the lookup function checks take, over f.
func lookupOf(f *fakeDNS) func(context.Context, string) ([]string, error) {
	return f.LookupTXT
}
