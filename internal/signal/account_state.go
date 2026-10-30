package signal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/store"
)

// Account states, the values of account.state. An operator sets them; no
// event does.
const (
	// StateActive is the state of every account no operator has set one
	// for, or whose state expired or was reset.
	StateActive = "active"
	// StateReview marks an account whose sends a person should look at
	// before they go out.
	StateReview = "review"
	// StateSuspended marks an account that must not send.
	StateSuspended = "suspended"
	// StateTrusted marks an account the operator vouches for, such as an
	// enterprise tenant whose volume looks like abuse to the heuristics.
	StateTrusted = "trusted"
)

// ErrInvalidAccountState is returned, wrapped, by AccountStates.Set for a
// state it does not accept.
var ErrInvalidAccountState = errors.New("signal: invalid account state")

// ErrUnreadableAccountState is returned, wrapped, by AccountStates.Get when
// the stored state is not one Set wrote. Setting or resetting the state
// replaces it.
var ErrUnreadableAccountState = errors.New("signal: unreadable account state")

// maxStateReasonBytes bounds AccountState.Reason, which is stored with the
// state and read with every event of the account.
const maxStateReasonBytes = 1024

// AccountState is the state an operator set for an account.
type AccountState struct {
	// State is StateActive, StateReview, StateSuspended or StateTrusted.
	State string `json:"state"`
	// Until is when the state expires and the account is active again;
	// zero keeps it until it is reset.
	Until time.Time `json:"until,omitzero"`
	// Reason says why, for the people who read it later.
	Reason string `json:"reason,omitempty"`
	// SetAt is when the state was set, and SetBy who set it, such as the
	// name of the API token. Both are zero for StateActive.
	SetAt time.Time `json:"set_at,omitzero"`
	SetBy string    `json:"set_by,omitempty"`
}

// AccountStates reads and writes the state of accounts in the store the
// catalog reads them from, where they are kept under the account's key,
// "account:state:<id>", as JSON. A state with an expiry is stored with the
// time left as its time to live, so the store forgets it when it expires.
type AccountStates struct {
	store store.Store
	now   func() time.Time
}

// NewAccountStates returns AccountStates that keep states in s, the store
// of a catalog. It does not close s.
func NewAccountStates(s store.Store) *AccountStates {
	return &AccountStates{store: s, now: time.Now}
}

// Get returns the state of account id: StateActive when none is set or it
// expired.
func (a *AccountStates) Get(ctx context.Context, id string) (AccountState, error) {
	if id == "" {
		return AccountState{}, errors.New("signal: account state: empty account id")
	}
	var b store.Batch
	r := b.Get(accountKey("state", id))
	if err := a.store.Do(ctx, &b); err != nil {
		return AccountState{}, fmt.Errorf("signal: read account state: %w", err)
	}
	st, ok := parseAccountState(r, a.now())
	if !ok {
		return AccountState{}, fmt.Errorf("%w for account %q", ErrUnreadableAccountState, id)
	}
	return st, nil
}

// Set stores st as the state of account id, replacing any other. Setting
// StateActive resets the account, as Reset does. SetAt is set to now when
// zero. It fails with ErrInvalidAccountState when st.State is not one of
// the states, Until has passed, or Reason is longer than 1024 bytes.
func (a *AccountStates) Set(ctx context.Context, id string, st AccountState) error {
	if id == "" {
		return errors.New("signal: account state: empty account id")
	}
	now := a.now()
	switch st.State {
	case StateActive:
		return a.Reset(ctx, id)
	case StateReview, StateSuspended, StateTrusted:
	default:
		return fmt.Errorf("%w: %q: want %s, %s, %s or %s", ErrInvalidAccountState, st.State,
			StateActive, StateReview, StateSuspended, StateTrusted)
	}
	var ttl time.Duration
	if !st.Until.IsZero() {
		// The store keeps a value to the millisecond.
		if ttl = st.Until.Sub(now).Truncate(time.Millisecond); ttl <= 0 {
			return fmt.Errorf("%w: until %s has passed", ErrInvalidAccountState, st.Until.Format(time.RFC3339))
		}
		st.Until = st.Until.UTC()
	}
	if len(st.Reason) > maxStateReasonBytes {
		return fmt.Errorf("%w: the reason is longer than %d bytes", ErrInvalidAccountState, maxStateReasonBytes)
	}
	if st.SetAt.IsZero() {
		st.SetAt = now
	}
	st.SetAt = st.SetAt.UTC()
	v, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("signal: account state: %w", err)
	}
	var b store.Batch
	b.Set(accountKey("state", id), string(v), ttl)
	if err := a.store.Do(ctx, &b); err != nil {
		return fmt.Errorf("signal: write account state: %w", err)
	}
	return nil
}

// Reset makes account id active again, whatever its state.
func (a *AccountStates) Reset(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("signal: account state: empty account id")
	}
	var b store.Batch
	b.Delete(accountKey("state", id))
	if err := a.store.Do(ctx, &b); err != nil {
		return fmt.Errorf("signal: reset account state: %w", err)
	}
	return nil
}

// parseAccountState reads a state stored by AccountStates.Set. It returns
// StateActive when none is stored, or when the stored one expired at now,
// which the store's time to live normally sees to, and false when the
// stored value cannot be read.
func parseAccountState(r *store.StringResult, now time.Time) (AccountState, bool) {
	if !r.Found() {
		return AccountState{State: StateActive}, true
	}
	var st AccountState
	if err := json.Unmarshal([]byte(r.Val()), &st); err != nil || st.State == "" {
		return AccountState{}, false
	}
	if !st.Until.IsZero() && !now.Before(st.Until) {
		return AccountState{State: StateActive}, true
	}
	return st, true
}
