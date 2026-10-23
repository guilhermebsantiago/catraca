// Package audit is Catraca's decision log: every decision with a minimal copy
// of its event, the labels people give it, and the per-rule counts the
// precision gate reads. It also holds the outbox of webhook deliveries, so an
// effect is durable in the same database as the decision behind it.
//
// Two backends share one schema and one implementation: SQLite (pure Go, the
// default, for a single instance) and Postgres (for several instances). Open
// picks one from a DSN.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/precision"
)

// Store is the decision log. *DB implements it.
type Store interface {
	// Record queues a decision and its event to be written. It never blocks:
	// when the buffer is full the decision is dropped, counted and logged.
	Record(ctx context.Context, ev event.Event, d decision.Decision)
	// Flush writes every decision queued before the call.
	Flush(ctx context.Context) error
	// Get returns a decision, its stored event and its labels, or an error
	// wrapping ErrNotFound.
	Get(ctx context.Context, decisionID string) (Entry, error)
	// Label attaches a label to a decision. A label without a rule id
	// applies to every rule that matched the decision.
	Label(ctx context.Context, decisionID string, l Label) error
	// RuleStats counts, per rule and mode, the matches decided at or after
	// since and how they were labeled.
	RuleStats(ctx context.Context, since time.Time) ([]precision.RuleStats, error)
	// ReviewQueue returns the most recent unlabeled matches of a rule in a
	// mode, newest first. An empty ruleID or mode matches any.
	ReviewQueue(ctx context.Context, ruleID string, mode decision.Mode, limit int) ([]ReviewItem, error)
	// Close writes queued decisions, until ctx ends, and closes the database.
	Close(ctx context.Context) error
}

var (
	// ErrNotFound is returned when a decision is not in the log.
	ErrNotFound = errors.New("audit: decision not found")
	// ErrRuleNotMatched is returned when a label names a rule that did not
	// match the decision.
	ErrRuleNotMatched = errors.New("audit: rule did not match the decision")
	// ErrInvalidLabel is returned when a label is malformed.
	ErrInvalidLabel = errors.New("audit: invalid label")
)

// Verdict is a person's judgment of a match.
type Verdict string

const (
	// TruePositive means the rule was right: the event was abuse.
	TruePositive Verdict = "true_positive"
	// FalsePositive means the rule was wrong. A reversal of an enforced
	// decision, such as unblocking a sender after an appeal, is a false
	// positive.
	FalsePositive Verdict = "false_positive"
)

// Label is a verdict on a decision, or on one rule that matched it.
type Label struct {
	// RuleID names the rule the verdict is about. Empty means the verdict is
	// about the event itself and applies to every rule that matched it.
	RuleID  string  `json:"rule_id,omitempty"`
	Verdict Verdict `json:"verdict"`
	// By is who gave the label: a person, or a system such as the platform's
	// appeals flow. Required.
	By     string `json:"by"`
	Reason string `json:"reason,omitempty"`
	// Time is when the verdict was given; Label fills it with the current
	// time when it is zero. When several labels apply to a match, the one
	// with the latest Time wins.
	Time time.Time `json:"time"`
}

// Reversal returns the label for undoing an enforced decision, for example
// unblocking a sender after an appeal: a false positive for every rule that
// matched.
func Reversal(by, reason string) Label {
	return Label{Verdict: FalsePositive, By: by, Reason: reason}
}

// Validate reports whether the label is well formed.
func (l Label) Validate() error {
	switch l.Verdict {
	case TruePositive, FalsePositive:
	default:
		return fmt.Errorf("%w: verdict must be %q or %q, got %q", ErrInvalidLabel, TruePositive, FalsePositive, l.Verdict)
	}
	if l.By == "" {
		return fmt.Errorf("%w: by is required", ErrInvalidLabel)
	}
	return nil
}

// Entry is one decision in the log with its stored event and labels.
type Entry struct {
	Decision decision.Decision `json:"decision"`
	Event    StoredEvent       `json:"event"`
	// Labels are every label given to the decision, oldest first.
	Labels []Label `json:"labels"`
}

// ReviewItem is an unlabeled match waiting for a reviewer's verdict.
type ReviewItem struct {
	DecisionID string          `json:"decision_id"`
	RuleID     string          `json:"rule_id"`
	Mode       decision.Mode   `json:"mode"`
	Action     decision.Action `json:"action"`
	Reason     string          `json:"reason"`
	Errored    bool            `json:"errored,omitempty"`
	Time       time.Time       `json:"time"`
	Event      StoredEvent     `json:"event"`
}

// EventMode says how much of an event the log keeps.
type EventMode string

const (
	// EventMinimal keeps the fields needed to review a decision and no
	// message content. It is the default.
	EventMinimal EventMode = "minimal"
	// EventFull also keeps the whole event as the platform sent it,
	// including recipients, subject and links.
	EventFull EventMode = "full"
)

// ParseEventMode parses an event mode name. Empty means EventMinimal.
func ParseEventMode(s string) (EventMode, error) {
	switch EventMode(s) {
	case "", EventMinimal:
		return EventMinimal, nil
	case EventFull:
		return EventFull, nil
	}
	return "", fmt.Errorf("audit: unknown event mode %q (want minimal or full)", s)
}

// Options configure a DB. Zero values take the defaults.
type Options struct {
	// EventMode is how much of each event to keep. Default EventMinimal.
	EventMode EventMode
	// BufferSize is how many decisions can wait to be written before Record
	// starts dropping them. Default 8192.
	BufferSize int
	// BatchSize is the most decisions written in one transaction.
	// Default 256.
	BatchSize int
	// FlushInterval is the longest a decision waits in the buffer.
	// Default 200ms.
	FlushInterval time.Duration
	// Pool bounds the connections to the database.
	Pool Pool
	// Retention is how long decisions without a label and finished webhook
	// deliveries are kept; older ones are deleted in the background. Zero
	// keeps everything.
	Retention time.Duration
	// LabeledRetention is how long labeled decisions are kept, with their
	// labels. Zero keeps them forever: the precision gate and backtests
	// need them. When set, it must be at least Retention.
	LabeledRetention time.Duration
	// Logger receives drop and write-failure reports. Default slog.Default().
	Logger *slog.Logger
}

// Pool bounds the connections to the audit database, so a slow database
// makes callers wait for a connection instead of opening more until the
// server refuses them. Zero values take the defaults. An in-memory SQLite
// database ignores it and keeps its one connection forever, since that
// connection is the database.
type Pool struct {
	// MaxOpen is the most connections open at once. Default 10.
	MaxOpen int
	// MaxIdle is the most idle connections kept for reuse. Default MaxOpen,
	// so a burst does not close and reopen connections; values above
	// MaxOpen are lowered to it.
	MaxIdle int
	// MaxLifetime closes connections this long after they opened, so they
	// follow a failover or a DNS change. Default 30m.
	MaxLifetime time.Duration
	// MaxIdleTime closes connections idle this long. Default 5m.
	MaxIdleTime time.Duration
}

// Defaults for Pool.
const (
	DefaultPoolMaxOpen     = 10
	DefaultPoolMaxLifetime = 30 * time.Minute
	DefaultPoolMaxIdleTime = 5 * time.Minute
)

// MinRetention is the shortest Retention accepted: decisions have to stay
// long enough to be reviewed and labeled.
const MinRetention = 24 * time.Hour

func (p Pool) withDefaults() Pool {
	if p.MaxOpen <= 0 {
		p.MaxOpen = DefaultPoolMaxOpen
	}
	if p.MaxIdle <= 0 {
		p.MaxIdle = p.MaxOpen
	}
	p.MaxIdle = min(p.MaxIdle, p.MaxOpen)
	if p.MaxLifetime <= 0 {
		p.MaxLifetime = DefaultPoolMaxLifetime
	}
	if p.MaxIdleTime <= 0 {
		p.MaxIdleTime = DefaultPoolMaxIdleTime
	}
	return p
}

func (o Options) withDefaults() Options {
	if o.EventMode == "" {
		o.EventMode = EventMinimal
	}
	if o.BufferSize <= 0 {
		o.BufferSize = 8192
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 256
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = 200 * time.Millisecond
	}
	o.Pool = o.Pool.withDefaults()
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

func (o Options) validate() error {
	if _, err := ParseEventMode(string(o.EventMode)); err != nil {
		return err
	}
	return validateRetention(o.Retention, o.LabeledRetention)
}

// validateRetention checks a pair of retention settings: zero or at least
// MinRetention, and labeled decisions kept at least as long as the others.
func validateRetention(retention, labeled time.Duration) error {
	switch {
	case retention < 0 || labeled < 0:
		return errors.New("audit: retention cannot be negative")
	case retention > 0 && retention < MinRetention:
		return fmt.Errorf("audit: retention must be at least %s, got %s", MinRetention, retention)
	case labeled > 0 && retention == 0:
		return errors.New("audit: labeled retention needs a retention for unlabeled decisions too")
	case labeled > 0 && labeled < retention:
		return fmt.Errorf("audit: labeled retention (%s) must be at least the retention (%s)", labeled, retention)
	}
	return nil
}
