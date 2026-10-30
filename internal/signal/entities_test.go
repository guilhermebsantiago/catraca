package signal_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

var testEntities = []signal.Entity{
	{Name: "content", Attribute: "content_hash"},
	{Name: "parent", Attribute: "parent_account"},
}

func withAttr(k, v string) func(*event.Event) {
	return func(e *event.Event) {
		if e.Attributes == nil {
			e.Attributes = map[string]string{}
		}
		e.Attributes[k] = v
	}
}

// entity returns the signals of entity name in set, or nil.
func entity(t *testing.T, set signal.Set, name string) map[string]any {
	t.Helper()
	m, _ := set.Entity[name].(map[string]any)
	return m
}

func TestEntities(t *testing.T) {
	for i, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			skipBackend(t, i)
			c := signal.NewCatalog(be.new(t), signal.Options{Entities: testEntities})
			t.Cleanup(func() { c.Close() })

			tpl := withAttr("content_hash", "tpl-1")
			// Three accounts send the same template; one sends it twice.
			observe(t, c, send(0, tpl))
			observe(t, c, send(time.Minute, tpl))
			observe(t, c, send(2*time.Minute, tpl, withAccount("acct-2")))
			// A signup carrying the hash links its account without a send.
			observe(t, c, accountEvent(3*time.Minute, "signup", withAccount("acct-3"), tpl))
			// Another template, and a send without one.
			observe(t, c, send(4*time.Minute, withAttr("content_hash", "tpl-2"), withAccount("acct-4")))
			set := observe(t, c, send(5*time.Minute))
			if set.Entity != nil {
				t.Errorf("a send without entity attributes: entity = %v, want nil", set.Entity)
			}

			set = observe(t, c, send(10*time.Minute, tpl, withAccount("acct-5"), withAttr("parent_account", "p-1")))
			want(t, "content", entity(t, set, "content"), map[string]any{
				"sends_1h": int64(4), "sends_24h": int64(4),
				"distinct_accounts_24h": int64(4), "distinct_accounts_7d": int64(4),
			})
			want(t, "parent", entity(t, set, "parent"), map[string]any{
				"sends_1h": int64(1), "sends_24h": int64(1),
				"distinct_accounts_24h": int64(1), "distinct_accounts_7d": int64(1),
			})

			// An empty value names no entity.
			set = observe(t, c, send(11*time.Minute, withAttr("content_hash", "")))
			if _, ok := set.Entity["content"]; ok {
				t.Errorf("an empty attribute: entity = %v, want no content", set.Entity)
			}

			// Windows: past an hour, past a day.
			set = observe(t, c, send(2*time.Hour, tpl))
			want(t, "content after 2h", entity(t, set, "content"), map[string]any{
				"sends_1h": int64(1), "sends_24h": int64(5), "distinct_accounts_24h": int64(4),
			})
			set = observe(t, c, send(2*day, tpl, withAccount("acct-9")))
			want(t, "content after 2d", entity(t, set, "content"), map[string]any{
				"sends_24h": int64(1), "distinct_accounts_24h": int64(1), "distinct_accounts_7d": int64(5),
			})

			// Feedback carries attributes too, but counts nothing here.
			set = observe(t, c, feedback(2*day+time.Minute, event.Complaint, "", tpl, withAccount("acct-10")))
			want(t, "content after feedback", entity(t, set, "content"), map[string]any{
				"sends_24h": int64(1), "distinct_accounts_24h": int64(1),
			})
		})
	}
}

// TestEntitiesKeepApart checks that two entities with the same value, or an
// entity and another catalog's counter, never share a key.
func TestEntitiesKeepApart(t *testing.T) {
	c := signal.NewCatalog(store.NewMemory(), signal.Options{Entities: []signal.Entity{
		{Name: "a", Attribute: "x"}, {Name: "b", Attribute: "y"},
	}})
	defer c.Close()
	observe(t, c, send(0, withAttr("x", "same")))
	set := observe(t, c, send(time.Minute, withAttr("y", "same")))
	if got := entity(t, set, "b")["sends_1h"]; got != int64(1) {
		t.Errorf("b.sends_1h = %v, want 1", got)
	}
	if _, ok := set.Entity["a"]; ok {
		t.Errorf("entity = %v, want only b", set.Entity)
	}
}

func TestEntitiesStoreNoValue(t *testing.T) {
	mr := storetest.Miniredis(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, ReadTimeout: storetest.MiniredisReadTimeout})
	defer client.Close()
	c := signal.NewCatalog(store.NewRedis(client, store.RedisOptions{}), signal.Options{Entities: testEntities})
	defer c.Close()
	ev := send(0, withAttr("content_hash", "victim@inbox.example"))
	observe(t, c, ev)
	for _, k := range mr.Keys() {
		if strings.Contains(k, "victim") {
			t.Errorf("key %q holds the attribute value", k)
		}
	}
	n := 0
	for _, k := range mr.Keys() {
		if strings.Contains(k, "entity:") {
			n++
		}
	}
	if n == 0 {
		t.Errorf("keys = %v, want entity counters", mr.Keys())
	}
}

func TestEntityValidate(t *testing.T) {
	for _, e := range []signal.Entity{
		{Name: "", Attribute: "a"},
		{Name: "Content", Attribute: "a"},
		{Name: "1x", Attribute: "a"},
		{Name: "a:b", Attribute: "a"},
		{Name: "a.b", Attribute: "a"},
		{Name: strings.Repeat("a", 33), Attribute: "a"},
		{Name: "ok", Attribute: ""},
		{Name: "ok", Attribute: strings.Repeat("a", event.MaxIDBytes+1)},
	} {
		if e.Validate() == nil {
			t.Errorf("%+v validates", e)
		}
	}
	for _, e := range []signal.Entity{{Name: "content", Attribute: "content_hash"}, {Name: "a_1", Attribute: "x"}} {
		if err := e.Validate(); err != nil {
			t.Errorf("%+v: %v", e, err)
		}
	}
}

func TestNewCatalogRejectsBadEntities(t *testing.T) {
	for name, ents := range map[string][]signal.Entity{
		"invalid":  {{Name: "Bad", Attribute: "x"}},
		"repeated": {{Name: "a", Attribute: "x"}, {Name: "a", Attribute: "y"}},
		"too many": make([]signal.Entity, signal.MaxEntities+1),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("NewCatalog did not panic")
				}
			}()
			signal.NewCatalog(store.NewMemory(), signal.Options{Entities: ents})
		})
	}
}

func TestReputationFeedback(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		observe(t, c, feedback(0, event.Trap, ""))
		observe(t, c, feedback(3*time.Hour, event.Trap, ""))
		observe(t, c, feedback(3*time.Hour, event.Blocklist, ""))
		observe(t, c, feedback(3*time.Hour, event.Trap, "", withAccount("acct-2")))
		set := observe(t, c, send(4*time.Hour))
		want(t, "account", set.Account, map[string]any{
			"trap_hits_7d": int64(2), "blocklist_hits_7d": int64(1),
			"bounces_7d": int64(0), "complaints_7d": int64(0),
		})
		set = observe(t, c, send(7*day+time.Hour))
		want(t, "account a week later", set.Account, map[string]any{
			"trap_hits_7d": int64(1), "blocklist_hits_7d": int64(1),
		})
	})
}

// TestDocsListEveryEntitySignal keeps the entity section of docs/signals.md
// in step with the catalog.
func TestDocsListEveryEntitySignal(t *testing.T) {
	doc, err := os.ReadFile("../../docs/signals.md")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(doc), "\n## `entity`\n")
	if !ok {
		t.Fatal("docs/signals.md has no section \"## `entity`\"")
	}
	body, _, _ = strings.Cut(body, "\n## ")
	for _, s := range signal.EntitySpecs() {
		if !strings.Contains(body, "| `"+s.Name+"` | "+s.Type+" |") {
			t.Errorf("docs/signals.md does not list entity signal %s as %s", s.Name, s.Type)
		}
	}
}
