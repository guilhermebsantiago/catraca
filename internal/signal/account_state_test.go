package signal_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// TestAccountState checks that a state set through AccountStates is what
// account.state reads, on every backend, until it is reset or expires.
func TestAccountState(t *testing.T) {
	for i, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			skipBackend(t, i)
			s := be.new(t)
			c := signal.NewCatalog(s, signal.Options{})
			t.Cleanup(func() { c.Close() })
			states := signal.NewAccountStates(s)
			ctx := context.Background()
			stateOf := func() any {
				t.Helper()
				return observe(t, c, send(0)).Account["state"]
			}

			if got := stateOf(); got != signal.StateActive {
				t.Errorf("account.state with no state set = %v, want active", got)
			}
			st, err := states.Get(ctx, "acct-1")
			if err != nil || st.State != signal.StateActive || !st.SetAt.IsZero() {
				t.Errorf("Get with no state set = %+v, %v; want active", st, err)
			}

			until := time.Now().Add(time.Hour).Truncate(time.Second)
			set := signal.AccountState{State: signal.StateSuspended, Until: until, Reason: "chargeback fraud", SetBy: "ops"}
			if err := states.Set(ctx, "acct-1", set); err != nil {
				t.Fatal(err)
			}
			if got := stateOf(); got != signal.StateSuspended {
				t.Errorf("account.state = %v, want suspended", got)
			}
			if other := observe(t, c, send(0, withAccount("acct-2"))).Account["state"]; other != signal.StateActive {
				t.Errorf("account.state of another account = %v, want active", other)
			}
			st, err = states.Get(ctx, "acct-1")
			if err != nil {
				t.Fatal(err)
			}
			if st.State != signal.StateSuspended || !st.Until.Equal(until) || st.Reason != "chargeback fraud" || st.SetBy != "ops" || st.SetAt.IsZero() {
				t.Errorf("Get = %+v, want the state set", st)
			}

			// A new state replaces the old one, expiry included.
			if err := states.Set(ctx, "acct-1", signal.AccountState{State: signal.StateTrusted}); err != nil {
				t.Fatal(err)
			}
			if st, _ := states.Get(ctx, "acct-1"); st.State != signal.StateTrusted || !st.Until.IsZero() || st.Reason != "" {
				t.Errorf("Get after replacing = %+v, want trusted with no expiry", st)
			}
			if got := stateOf(); got != signal.StateTrusted {
				t.Errorf("account.state = %v, want trusted", got)
			}

			if err := states.Reset(ctx, "acct-1"); err != nil {
				t.Fatal(err)
			}
			if got := stateOf(); got != signal.StateActive {
				t.Errorf("account.state after Reset = %v, want active", got)
			}

			// Setting active resets too.
			if err := states.Set(ctx, "acct-1", signal.AccountState{State: signal.StateReview}); err != nil {
				t.Fatal(err)
			}
			if err := states.Set(ctx, "acct-1", signal.AccountState{State: signal.StateActive}); err != nil {
				t.Fatal(err)
			}
			if got := stateOf(); got != signal.StateActive {
				t.Errorf("account.state after setting active = %v, want active", got)
			}
		})
	}
}

// TestAccountStateExpires checks that a state with an expiry stops applying
// once it passes, by the wall clock, as the store forgets it.
func TestAccountStateExpires(t *testing.T) {
	s := store.NewMemory()
	c := signal.NewCatalog(s, signal.Options{})
	t.Cleanup(func() { c.Close() })
	states := signal.NewAccountStates(s)
	ctx := context.Background()
	if err := states.Set(ctx, "acct-1", signal.AccountState{State: signal.StateReview, Until: time.Now().Add(50 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	if got := observe(t, c, send(0)).Account["state"]; got != signal.StateReview {
		t.Fatalf("account.state = %v, want review", got)
	}
	time.Sleep(60 * time.Millisecond)
	if got := observe(t, c, send(time.Second)).Account["state"]; got != signal.StateActive {
		t.Errorf("account.state after the state expired = %v, want active", got)
	}
	if st, err := states.Get(ctx, "acct-1"); err != nil || st.State != signal.StateActive {
		t.Errorf("Get after the state expired = %+v, %v; want active", st, err)
	}
}

func TestAccountStateInvalid(t *testing.T) {
	states := signal.NewAccountStates(store.NewMemory())
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		st   signal.AccountState
		want string
	}{
		{"unknown state", signal.AccountState{State: "banned"}, `"banned"`},
		{"empty state", signal.AccountState{}, `""`},
		{"past expiry", signal.AccountState{State: signal.StateReview, Until: time.Now().Add(-time.Minute)}, "has passed"},
		{"long reason", signal.AccountState{State: signal.StateReview, Reason: strings.Repeat("x", 1025)}, "reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := states.Set(ctx, "acct-1", tc.st)
			if !errors.Is(err, signal.ErrInvalidAccountState) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Set = %v, want ErrInvalidAccountState about %s", err, tc.want)
			}
		})
	}
	if err := states.Set(ctx, "", signal.AccountState{State: signal.StateReview}); err == nil {
		t.Error("Set with an empty account id succeeded")
	}
}

// TestAccountStateUnreadable checks that a stored state the catalog cannot
// read leaves account.state absent, so rules that read it follow on_error.
func TestAccountStateUnreadable(t *testing.T) {
	s := store.NewMemory()
	c := signal.NewCatalog(s, signal.Options{})
	t.Cleanup(func() { c.Close() })
	var b store.Batch
	b.Set("account:state:acct-1", "not json", 0)
	if err := s.Do(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	set := observe(t, c, send(0))
	if v, ok := set.Account["state"]; ok {
		t.Errorf("account.state = %v, want absent", v)
	}
	if _, ok := set.Account["sends_1m"]; !ok {
		t.Error("the other account signals are absent")
	}
	if _, err := signal.NewAccountStates(s).Get(context.Background(), "acct-1"); err == nil {
		t.Error("Get of an unreadable state succeeded")
	}
}
