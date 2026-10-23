// Package decision defines what Catraca answers for an event: an action, the
// rules behind it, and the rules that would have acted in shadow mode.
package decision

import (
	"encoding/json"
	"fmt"
	"time"
)

// Action is what the platform should do with the event. Actions are ordered:
// when several enforced rules match, the most severe one wins.
type Action string

const (
	// Allow lets the event through.
	Allow Action = "allow"
	// Flag lets the event through and records it for review.
	Flag Action = "flag"
	// Throttle asks the platform to retry after Decision.RetryAfter.
	Throttle Action = "throttle"
	// Hold asks the platform to queue the email until a person reviews it.
	Hold Action = "hold"
	// Block refuses the event.
	Block Action = "block"
)

var severity = map[Action]int{Allow: 0, Flag: 1, Throttle: 2, Hold: 3, Block: 4}

// Severity orders actions from Allow (0) to Block (4).
func (a Action) Severity() int { return severity[a] }

// Valid reports whether a is a known action.
func (a Action) Valid() bool { _, ok := severity[a]; return ok }

// Max returns the more severe of a and b.
func Max(a, b Action) Action {
	if b.Severity() > a.Severity() {
		return b
	}
	return a
}

// ParseAction parses an action name.
func ParseAction(s string) (Action, error) {
	a := Action(s)
	if !a.Valid() {
		return "", fmt.Errorf("unknown action %q (want allow, flag, throttle, hold or block)", s)
	}
	return a, nil
}

// Mode says whether a rule acts or only records what it would have done.
type Mode string

const (
	// Shadow rules are evaluated and recorded but never change the action.
	Shadow Mode = "shadow"
	// Enforce rules change the action.
	Enforce Mode = "enforce"
)

// ParseMode parses a mode name.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Shadow, Enforce:
		return Mode(s), nil
	}
	return "", fmt.Errorf("unknown mode %q (want shadow or enforce)", s)
}

// OnError says what a rule does when it cannot be evaluated, for example
// because a signal was unavailable.
type OnError string

const (
	// FailOpen skips the rule: a broken detection never stops a good sender.
	FailOpen OnError = "open"
	// FailClosed treats the rule as matched: for detections where letting
	// abuse through is worse, such as a leaked key.
	FailClosed OnError = "closed"
)

// Match is one rule that matched the event.
type Match struct {
	RuleID  string   `json:"rule_id"`
	Reason  string   `json:"reason"`
	Action  Action   `json:"action"`
	Mode    Mode     `json:"mode"`
	Effects []string `json:"effects,omitempty"`
	// RetryAfter is encoded in JSON as whole seconds, like the HTTP
	// Retry-After header.
	RetryAfter time.Duration `json:"-"`
	// Errored is true when the rule could not be evaluated and matched only
	// because it fails closed. Its action applies, its effects do not.
	Errored bool `json:"errored,omitempty"`
}

// Decision is Catraca's answer for one event. Every decision carries the
// rules behind it, so each block and each reversal can be traced to a rule.
type Decision struct {
	ID      string    `json:"id"`
	EventID string    `json:"event_id,omitempty"`
	Time    time.Time `json:"time"`
	Action  Action    `json:"action"`
	// RetryAfter is set when Action is Throttle. It is encoded in JSON as
	// whole seconds, rounded up, like the HTTP Retry-After header.
	RetryAfter time.Duration `json:"-"`
	// Matches are the enforced rules that matched.
	Matches []Match `json:"matches,omitempty"`
	// Shadow are the shadow rules that matched: what would have happened.
	Shadow []Match `json:"shadow,omitempty"`
	// Errors lists rules that could not be evaluated, with the reason.
	Errors []RuleError `json:"errors,omitempty"`
	// Degraded is true when signals were missing, for example because the
	// store timed out, so some rules ran without them.
	Degraded bool `json:"degraded,omitempty"`
	// Uncounted is true when the decision is degraded because the store
	// failed, not because it answered late: the event may be missing from
	// the counters. A store that answers late still applies the event's
	// writes. An event sent again with the same id counts at most once.
	Uncounted bool `json:"uncounted,omitempty"`
	// Duplicate is true when an event with the same id had counted already,
	// so this one did not count again. The decision is made on the counters
	// as they are.
	Duplicate      bool   `json:"duplicate,omitempty"`
	RulesetVersion string `json:"ruleset_version"`
	LatencyMicros  int64  `json:"latency_us"`
}

// RuleError is a rule that could not be evaluated.
type RuleError struct {
	RuleID string `json:"rule_id"`
	Error  string `json:"error"`
}

// Effects returns the effects of the enforced matches, without duplicates.
// A match that is Errored contributes none: it stands for a rule that could
// not be evaluated, and running effects such as revoking a key on that
// alone would, during a store outage, run them for every event the rule
// covers.
func (d Decision) Effects() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range d.Matches {
		if m.Errored {
			continue
		}
		for _, e := range m.Effects {
			if !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// RetrySeconds rounds d up to whole seconds, the unit of retry_after in JSON
// and of the HTTP Retry-After header. Zero stays zero; any positive duration
// is at least one second, so a throttle never reads as "retry now".
func RetrySeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// MarshalJSON encodes RetryAfter as whole seconds.
func (m Match) MarshalJSON() ([]byte, error) {
	type plain Match
	return json.Marshal(struct {
		plain
		RetryAfter int64 `json:"retry_after,omitempty"`
	}{plain(m), RetrySeconds(m.RetryAfter)})
}

// UnmarshalJSON reads retry_after as whole seconds.
func (m *Match) UnmarshalJSON(data []byte) error {
	type plain Match
	aux := struct {
		*plain
		RetryAfter int64 `json:"retry_after,omitempty"`
	}{plain: (*plain)(m)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	m.RetryAfter = time.Duration(aux.RetryAfter) * time.Second
	return nil
}

// MarshalJSON encodes RetryAfter as whole seconds.
func (d Decision) MarshalJSON() ([]byte, error) {
	type plain Decision
	return json.Marshal(struct {
		plain
		RetryAfter int64 `json:"retry_after,omitempty"`
	}{plain(d), RetrySeconds(d.RetryAfter)})
}

// UnmarshalJSON reads retry_after as whole seconds.
func (d *Decision) UnmarshalJSON(data []byte) error {
	type plain Decision
	aux := struct {
		*plain
		RetryAfter int64 `json:"retry_after,omitempty"`
	}{plain: (*plain)(d)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	d.RetryAfter = time.Duration(aux.RetryAfter) * time.Second
	return nil
}
