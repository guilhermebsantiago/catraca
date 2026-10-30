package store_test

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// FuzzSignalsAgree observes a sequence of events with the catalog on every
// store backend and compares every signal after each event, as
// FuzzStoresAgree compares the store's reads: the wall clock moves with
// event time, and an event that is not late gets the same signals from
// every backend. A late one gets the same from every Redis backend; the
// memory store may count it differently and may not see an IP Redis sees,
// and agrees on the rest.
//
// The sequences have every event type, ids and their retries, time moving
// across every window from a minute to a week, past the dedupe ttl, the
// retention and the 30 days new_ip looks back, events up to a week late,
// as the engine accepts them, keys marked leaked, and hard bounces and
// complaints, which the recipient memory keeps for 30 days.
func FuzzSignalsAgree(f *testing.F) {
	r := rand.New(rand.NewPCG(3, 5))
	for range 4 {
		seed := make([]byte, 1000)
		for i := range seed {
			seed[i] = byte(r.Uint32())
		}
		f.Add(seed)
	}
	backends := store.DiffBackends()
	f.Fuzz(func(t *testing.T, data []byte) {
		type runner struct {
			store.DiffBackend
			c       signal.Catalog
			advance func(time.Duration)
		}
		var runs []runner
		for _, be := range backends {
			if be.Skip() != "" {
				continue
			}
			s, advance := be.New(t)
			c := signal.NewCatalog(s, signal.Options{Retention: 10 * day, DedupeTTL: 10 * time.Minute, Entities: genEntities})
			runs = append(runs, runner{be, c, advance})
		}
		g := &eventGen{data: data, at: t0, newest: t0}
		ctx := context.Background()
		// The stores start with an event at t0, where the wall clock
		// starts, as FuzzStoresAgree's do.
		for _, r := range runs {
			setup := event.Event{Type: event.Account, Time: t0, AccountID: "acct-setup"}
			if _, err := r.c.Observe(ctx, setup); err != nil {
				t.Fatalf("%s: Observe: %v", r.Name, err)
			}
		}
		for i := 0; g.more() && i < 150; i++ {
			ev, leak := g.next()
			if leak != "" {
				for _, r := range runs {
					r.advance(0)
					if err := r.c.MarkLeaked(ctx, leak); err != nil {
						t.Fatalf("%s: MarkLeaked: %v", r.Name, err)
					}
				}
				continue
			}
			if ev == nil {
				continue
			}
			late := ev.Time.Before(g.newest)
			d := time.Duration(0)
			if ev.Time.After(g.newest) {
				// The wall clock follows the newest event time, by whole
				// seconds.
				d = ev.Time.Truncate(time.Second).Sub(g.newest.Truncate(time.Second))
				g.newest = ev.Time
			}
			sets := make([]signal.Set, len(runs))
			for j, r := range runs {
				r.advance(d)
				set, err := r.c.Observe(ctx, *ev)
				if err != nil {
					t.Fatalf("%s: Observe: %v", r.Name, err)
				}
				sets[j] = set
			}
			for j := range runs {
				if j == 1 {
					continue
				}
				if why := setsDiffer(sets[j], sets[1], late && runs[j].Memory); why != "" {
					t.Fatalf("event %d, %s at %v (late %v): %s and %s differ: %s\n%+v\n%+v\nevent %+v",
						i, ev.Type, ev.Time.Sub(t0), late, runs[j].Name, runs[1].Name, why, sets[j], sets[1], *ev)
				}
			}
		}
	})
}

// t0 is aligned to the buckets of every window, the widest being the 7 day
// window's 2h48m.
var t0 = time.Unix(1_767_225_600-1_767_225_600%10_080, 0).UTC()

const (
	day  = 24 * time.Hour
	week = 7 * day
)

// Pools the events draw from, small so that counters and distinct sets
// overlap. IPs and accounts may hold ':', and one IP case differs.
var (
	genAccounts = []string{"acct-1", "acct:2", "acct-3"}
	genKeys     = []string{"", "key-1", "key-2", "key:3"}
	genIPs      = []string{"", "203.0.113.7", "2001:db8::1", "2001:DB8::1"}
	genFroms    = []string{"", "news@one.example", "Team <Team@Two.example>", "billing@one.example"}
	genRcpts    = []string{"a@m1.example", "b@m2.example", "C@M1.example", "d@m3.example", "e@m4.example", "f@m2.example"}
	// Two entities may share a value, and a value may hold ':'.
	genEntities     = []signal.Entity{{Name: "content", Attribute: "content_hash"}, {Name: "parent", Attribute: "parent_account"}}
	genEntityValues = []string{"tpl-1", "tpl:2", "", "acct-1"}
	genJumps        = []time.Duration{
		time.Minute, 61 * time.Second, time.Hour, 61 * time.Minute, 24 * time.Hour, 24*time.Hour + 24*time.Minute,
		week, week + 2*time.Hour + 48*time.Minute, 10 * time.Minute, 10 * day, 30 * day, 31 * day,
	}
)

// eventGen reads a sequence of events from fuzz data.
type eventGen struct {
	data       []byte
	at, newest time.Time
	n          int
	sent       []event.Event
}

func (g *eventGen) byte() byte {
	if len(g.data) == 0 {
		return 0
	}
	b := g.data[0]
	g.data = g.data[1:]
	return b
}

func (g *eventGen) more() bool { return len(g.data) > 0 }

func pick[T any](g *eventGen, xs []T) T { return xs[int(g.byte())%len(xs)] }

// next returns the next event, or a key to mark leaked, or neither when the
// step only moved time.
func (g *eventGen) next() (*event.Event, string) {
	switch op := g.byte(); {
	case op < 0x40:
		// A little time, within the shortest window.
		g.at = g.at.Add(time.Duration(int(g.byte())<<8|int(g.byte())) * time.Millisecond)
		return nil, ""
	case op < 0x4c:
		g.at = g.at.Add(pick(g, genJumps))
		return nil, ""
	case op < 0x4e:
		// Back by up to a week: the events until time catches up are late.
		g.at = g.at.Add(-min(week, time.Duration(1+int(g.byte())%32)*pick(g, genJumps[:6])))
		return nil, ""
	case op < 0x58:
		// Back to the newest time: late events end.
		g.at = maxTime(g.at, g.newest)
		return nil, ""
	case op < 0x5c:
		return nil, pick(g, genKeys[1:])
	case op < 0x74 && len(g.sent) > 0:
		// A retry of a recent event: the same event, with its time or, as
		// when the platform sends none and the engine stamps it, with the
		// current one.
		ev := g.sent[len(g.sent)-1-int(g.byte())%min(4, len(g.sent))]
		if ev.ID == "" {
			return nil, ""
		}
		if g.byte()%2 == 0 {
			ev.Time = g.at
		}
		return &ev, ""
	}
	ev := event.Event{Time: g.at, AccountID: pick(g, genAccounts), APIKeyID: pick(g, genKeys), IP: pick(g, genIPs), From: pick(g, genFroms)}
	switch kind := g.byte(); {
	case kind < 150:
		ev.Type = event.Send
		for range int(g.byte()) % 5 {
			ev.To = append(ev.To, pick(g, genRcpts))
		}
	case kind < 190:
		ev.Type = event.Feedback
		ev.IP = ""
		ev.Feedback = &event.FeedbackInfo{
			Kind:       pick(g, []event.FeedbackKind{event.Bounce, event.Complaint, event.Delivery, event.Trap, event.Blocklist}),
			BounceType: pick(g, []string{"permanent", "transient", "Permanent"}),
			Recipient:  pick(g, genRcpts),
		}
	case kind < 240:
		ev.Type = event.Account
		ev.Account = &event.AccountInfo{Action: pick(g, []string{"signup", "login", "api_key_created"})}
		if b := g.byte(); b%3 == 0 {
			created := g.at.Add(-time.Duration(b) * time.Hour)
			ev.Account.CreatedAt = &created
		}
	default:
		ev.Type = event.KeyLeak
		ev.APIKeyID = pick(g, genKeys[1:])
		if g.byte()%2 == 0 {
			ev.AccountID = ""
		}
	}
	if b := g.byte(); b%4 != 0 {
		// Feedback carries attributes too; the entities ignore it.
		ev.Attributes = map[string]string{genEntities[b%2].Attribute: pick(g, genEntityValues)}
	}
	if g.byte()%3 != 0 {
		g.n++
		ev.ID = fmt.Sprintf("ev-%d", g.n)
	}
	ev.Normalize(g.at)
	g.sent = append(g.sent, ev)
	return &ev, ""
}

// setsDiffer says how want differs from got, or returns "". With
// memoryLate, want is the memory store's set for a late event: its counts
// and what is derived from them may differ, and it may find an IP new that
// Redis has seen.
func setsDiffer(want, got signal.Set, memoryLate bool) string {
	if !memoryLate {
		if reflect.DeepEqual(want, got) {
			return ""
		}
		for _, m := range [...]struct {
			name      string
			want, got map[string]any
		}{{"event", want.Event, got.Event}, {"account", want.Account, got.Account}, {"key", want.Key, got.Key}, {"ip", want.IP, got.IP}, {"domain", want.Domain, got.Domain}, {"entity", want.Entity, got.Entity}} {
			for k, w := range m.want {
				if g, ok := m.got[k]; !ok || !reflect.DeepEqual(w, g) {
					return fmt.Sprintf("%s.%s: %v, %v", m.name, k, w, g)
				}
			}
			if len(m.want) != len(m.got) {
				return fmt.Sprintf("%s: %d signals, %d signals", m.name, len(m.want), len(m.got))
			}
		}
		return fmt.Sprintf("duplicate: %v, %v", want.Duplicate, got.Duplicate)
	}
	// The memory store may have forgotten a recipient that a late event's
	// window still reaches, as it may an IP, so it may find fewer.
	wantEvent, gotEvent := maps.Clone(want.Event), maps.Clone(got.Event)
	ws, _ := wantEvent["suppressed_recipients"].(int64)
	gs, _ := gotEvent["suppressed_recipients"].(int64)
	for _, k := range []string{"suppressed_recipients", "suppressed_ratio"} {
		delete(wantEvent, k)
		delete(gotEvent, k)
	}
	if !reflect.DeepEqual(wantEvent, gotEvent) || ws > gs || want.Duplicate != got.Duplicate {
		return "event signals or duplicate"
	}
	for _, m := range [...]struct {
		name      string
		want, got map[string]any
	}{{"account", want.Account, got.Account}, {"key", want.Key, got.Key}, {"ip", want.IP, got.IP}, {"domain", want.Domain, got.Domain}, {"entity", want.Entity, got.Entity}} {
		if (m.want == nil) != (m.got == nil) || len(m.want) != len(m.got) {
			return m.name + ": not the same signals"
		}
		for k, w := range m.want {
			g, ok := m.got[k]
			if !ok {
				return fmt.Sprintf("%s.%s: absent", m.name, k)
			}
			switch k {
			case "leaked":
				if w != g {
					return fmt.Sprintf("%s.leaked: %v, %v", m.name, w, g)
				}
			case "new_ip":
				if g == true && w != true {
					return fmt.Sprintf("%s.new_ip: %v, %v", m.name, w, g)
				}
			}
		}
	}
	return ""
}

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}
