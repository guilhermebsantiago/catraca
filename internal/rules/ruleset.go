// Package rules loads, checks and evaluates Catraca rulesets.
//
// A ruleset is a YAML file kept in git and reviewed like code. Each rule has
// a CEL expression over the signals of an event, the action it takes when it
// matches, a mode (shadow rules only record what they would have done) and an
// on_error policy for when it cannot be evaluated. Rulesets are parsed
// strictly and compiled at load, so a typo fails the load instead of a rule
// silently never matching. See docs/rules.md for the file format.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"cel.dev/cel-go/cel"

	"github.com/guilhermebsantiago/catraca/internal/decision"
)

// Format is the only ruleset file format so far, written as `version: 1`.
const Format = 1

// Ruleset is a parsed and compiled ruleset. It is immutable and safe for
// concurrent use; reloading builds a new Ruleset.
type Ruleset struct {
	version  string
	defaults defaults
	lists    map[string][]string
	rules    []*Rule
	byID     map[string]*Rule
	// listLines is where each list is declared, for lint warnings.
	listLines map[string]int
}

type defaults struct {
	mode    decision.Mode
	onError decision.OnError
}

// Rule is one compiled rule. Rules belong to their Ruleset and must not be
// modified.
type Rule struct {
	ID          string
	Description string
	// When is the CEL expression that decides whether the rule matches.
	When    string
	Action  decision.Action
	Mode    decision.Mode
	OnError decision.OnError
	// Effects are the hooks to call when the rule is enforced and matches.
	Effects []string
	// RetryAfter is set for throttle rules.
	RetryAfter time.Duration
	// Reason is shown to the platform and written to the audit log.
	Reason string
	Owner  string
	Tags   []string
	// Override records a decision to enforce the rule before it passed the
	// precision gate.
	Override *Override
	// Line is where the rule starts in its file.
	Line int

	program cel.Program
	expr    exprInfo
	// onErrorSet is true when on_error is written on the rule itself rather
	// than inherited from defaults.
	onErrorSet bool
}

// Override is a recorded decision to enforce a rule that has not passed the
// precision gate: who decided, why and when.
type Override struct {
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// Parse parses, validates and compiles a ruleset. On failure the error is an
// ErrorList with every problem found.
func Parse(data []byte) (*Ruleset, error) {
	return parse(data, "")
}

// LoadFile reads and parses the ruleset at path. Errors in the file are
// reported as an ErrorList whose entries carry the path.
func LoadFile(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data, path)
}

// Version is a short hash of the ruleset's canonical content: the rules with
// defaults applied and the lists, but not comments, formatting or the order
// of keys. It is stored in every decision.
func (rs *Ruleset) Version() string { return rs.version }

// Rules returns the rules in file order. The slice must not be modified.
func (rs *Ruleset) Rules() []*Rule { return rs.rules }

// Rule returns the rule with the given id.
func (rs *Ruleset) Rule(id string) (*Rule, bool) {
	r, ok := rs.byID[id]
	return r, ok
}

// Lists returns the named lists rules can read with in_list and any_in_list.
// The map must not be modified.
func (rs *Ruleset) Lists() map[string][]string { return rs.lists }

// MarshalJSON encodes the effective ruleset: its version, lists and rules
// with defaults applied.
func (rs *Ruleset) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Version string `json:"version"`
		document
	}{rs.version, rs.document()})
}

// document is the canonical content of a ruleset, the input of its version.
type document struct {
	Format int                 `json:"format"`
	Lists  map[string][]string `json:"lists"`
	Rules  []*Rule             `json:"rules"`
}

func (rs *Ruleset) document() document {
	return document{Format: Format, Lists: rs.lists, Rules: rs.rules}
}

// computeVersion hashes the canonical JSON encoding: encoding/json sorts map
// keys and Rule.MarshalJSON writes fields in a fixed order.
func (rs *Ruleset) computeVersion() (string, error) {
	data, err := json.Marshal(rs.document())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:6]), nil
}

// MarshalJSON encodes the rule with retry_after as a Go duration string.
func (r *Rule) MarshalJSON() ([]byte, error) {
	var retryAfter string
	if r.RetryAfter > 0 {
		retryAfter = r.RetryAfter.String()
	}
	return json.Marshal(struct {
		ID          string           `json:"id"`
		Description string           `json:"description,omitempty"`
		When        string           `json:"when"`
		Action      decision.Action  `json:"action"`
		Mode        decision.Mode    `json:"mode"`
		OnError     decision.OnError `json:"on_error"`
		Effects     []string         `json:"effects,omitempty"`
		RetryAfter  string           `json:"retry_after,omitempty"`
		Reason      string           `json:"reason"`
		Owner       string           `json:"owner,omitempty"`
		Tags        []string         `json:"tags,omitempty"`
		Override    *Override        `json:"override,omitempty"`
	}{
		r.ID, r.Description, r.When, r.Action, r.Mode, r.OnError, r.Effects,
		retryAfter, r.Reason, r.Owner, r.Tags, r.Override,
	})
}
