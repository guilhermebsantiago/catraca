package signal

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// MaxEntities is the most entities a catalog counts. Each one a send names
// costs it eight store operations more; see docs/signals.md.
const MaxEntities = 16

// Entity counts events by the value of one of their attributes, such as a
// content hash, a payment fingerprint or a parent account, so rules can see
// many accounts behind one value. Its signals are in the CEL map
// entity.<Name>; see EntitySpecs.
type Entity struct {
	// Name is how rules refer to the entity: a lowercase CEL identifier.
	Name string
	// Attribute is the key of event.attributes whose value the entity is
	// keyed by. An event without it, or with it empty, leaves the entity
	// out of entity.
	Attribute string
}

var entityNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Validate reports whether e can be counted: its name is a lowercase
// identifier of at most 32 bytes, and it names an attribute.
func (e Entity) Validate() error {
	if !entityNameRE.MatchString(e.Name) {
		return fmt.Errorf("name %q must be a lowercase letter followed by at most 31 lowercase letters, digits or _", e.Name)
	}
	if e.Attribute == "" {
		return fmt.Errorf("entity %s: attribute is required", e.Name)
	}
	if len(e.Attribute) > event.MaxIDBytes {
		return fmt.Errorf("entity %s: attribute is longer than %d bytes", e.Name, event.MaxIDBytes)
	}
	return nil
}

// EntitySpecs returns the signals every entity has, under entity.<name>.
// Their Map is "entity".
func EntitySpecs() []Spec {
	out := make([]Spec, len(entitySpecs))
	copy(out, entitySpecs)
	return out
}

var entitySpecs = []Spec{
	{"entity", "sends_1h", "int"},
	{"entity", "sends_24h", "int"},
	{"entity", "distinct_accounts_24h", "int"},
	{"entity", "distinct_accounts_7d", "int"},
}

// entityKey is the key of an entity counter. The value is hashed: it may be
// personal (a signup email domain, a device id) and it may be long, and the
// store keeps neither. The entity name, which never contains ':', keeps two
// entities with the same value apart.
func entityKey(counter, name, value string) string {
	sum := sha256.Sum256([]byte(value))
	return "entity:" + counter + ":" + name + ":" + base64.RawURLEncoding.EncodeToString(sum[:16])
}

type entityReads struct {
	name                    string
	sends1h, sends24h       *store.IntResult
	accounts24h, accounts7d *store.IntResult
}

// entities queues the writes and reads of every entity whose attribute ev
// carries. A send counts in sends; any event with an account counts in the
// distinct accounts, so a signup that carries a device id links its account
// before it sends.
func (c *catalog) entities(b *store.Batch, ev event.Event) []entityReads {
	var out []entityReads
	for _, e := range c.entityDefs {
		value := ev.Attributes[e.Attribute]
		if value == "" {
			continue
		}
		at := ev.Time
		sends, accounts := entityKey("sends", e.Name, value), entityKey("accounts", e.Name, value)
		if ev.Type == event.Send {
			b.Incr(sends, time.Hour, at, 1)
			b.Incr(sends, day, at, 1)
		}
		if ev.AccountID != "" && (ev.Type == event.Send || ev.Type == event.Account) {
			b.AddDistinct(accounts, ev.AccountID, day, at)
			b.AddDistinct(accounts, ev.AccountID, week, at)
		}
		out = append(out, entityReads{
			name:        e.Name,
			sends1h:     b.Count(sends, time.Hour, at),
			sends24h:    b.Count(sends, day, at),
			accounts24h: b.Distinct(accounts, day, at),
			accounts7d:  b.Distinct(accounts, week, at),
		})
	}
	return out
}

// entitySignals returns the entity map: one map of signals per entity the
// event names, or nil when it names none.
func entitySignals(reads []entityReads) map[string]any {
	if len(reads) == 0 {
		return nil
	}
	m := make(map[string]any, len(reads))
	for _, r := range reads {
		m[r.name] = map[string]any{
			"sends_1h":              r.sends1h.Val(),
			"sends_24h":             r.sends24h.Val(),
			"distinct_accounts_24h": r.accounts24h.Val(),
			"distinct_accounts_7d":  r.accounts7d.Val(),
		}
	}
	return m
}
