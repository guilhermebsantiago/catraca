package signal_test

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

func TestAccountSendCounters(t *testing.T) {
	steps := []struct {
		ev   event.Event
		want map[string]any
	}{
		{send(0, withTo("a@x.example", "b@y.example", "c@x.example"), withIP("203.0.113.1"), withKey("k1")), map[string]any{
			"sends_1m": int64(1), "sends_1h": int64(1), "sends_24h": int64(1), "sends_7d": int64(1),
			"recipients_1h": int64(3), "recipients_24h": int64(3),
			"distinct_recipient_domains_1h": int64(2), "distinct_recipient_domains_24h": int64(2),
			"distinct_ips_24h": int64(1), "distinct_keys_24h": int64(1),
		}},
		{send(30*time.Second, withTo("d@z.example"), withIP("203.0.113.2"), withKey("k2")), map[string]any{
			"sends_1m": int64(2), "sends_1h": int64(2), "sends_24h": int64(2), "sends_7d": int64(2),
			"recipients_1h": int64(4), "recipients_24h": int64(4),
			"distinct_recipient_domains_1h": int64(3), "distinct_recipient_domains_24h": int64(3),
			"distinct_ips_24h": int64(2), "distinct_keys_24h": int64(2),
		}},
		{send(2*time.Minute, withTo("e@x.example"), withIP("203.0.113.1"), withKey("k1")), map[string]any{
			"sends_1m": int64(1), "sends_1h": int64(3), "sends_24h": int64(3), "sends_7d": int64(3),
			"recipients_1h": int64(5), "recipients_24h": int64(5),
			"distinct_recipient_domains_1h": int64(3), "distinct_recipient_domains_24h": int64(3),
			"distinct_ips_24h": int64(2), "distinct_keys_24h": int64(2),
		}},
		{send(2*time.Hour, withTo("f@w.example"), withIP("203.0.113.1"), withKey("k1")), map[string]any{
			"sends_1m": int64(1), "sends_1h": int64(1), "sends_24h": int64(4), "sends_7d": int64(4),
			"recipients_1h": int64(1), "recipients_24h": int64(6),
			"distinct_recipient_domains_1h": int64(1), "distinct_recipient_domains_24h": int64(4),
			"distinct_ips_24h": int64(2), "distinct_keys_24h": int64(2),
		}},
		{send(25*time.Hour, withTo("g@v.example"), withIP("203.0.113.3"), withKey("k1")), map[string]any{
			"sends_1m": int64(1), "sends_1h": int64(1), "sends_24h": int64(2), "sends_7d": int64(5),
			"recipients_1h": int64(1), "recipients_24h": int64(2),
			"distinct_recipient_domains_1h": int64(1), "distinct_recipient_domains_24h": int64(2),
			"distinct_ips_24h": int64(2), "distinct_keys_24h": int64(1),
		}},
		{send(week+2*time.Hour+time.Minute, withTo("h@u.example"), withIP("203.0.113.1"), withKey("k1")), map[string]any{
			"sends_1m": int64(1), "sends_1h": int64(1), "sends_24h": int64(1), "sends_7d": int64(2),
			"recipients_1h": int64(1), "recipients_24h": int64(1),
			"distinct_recipient_domains_1h": int64(1), "distinct_recipient_domains_24h": int64(1),
			"distinct_ips_24h": int64(1), "distinct_keys_24h": int64(1),
		}},
	}
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		for _, st := range steps {
			want(t, "at "+st.ev.Time.Sub(t0).String(), observe(t, c, st.ev).Account, st.want)
		}
	})
}

func TestFeedbackCounters(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		for i := range 4 {
			observe(t, c, send(time.Duration(i)*time.Second))
		}
		for i, ev := range []event.Event{
			feedback(time.Minute, event.Bounce, "permanent"),
			feedback(time.Minute, event.Bounce, "transient"),
			feedback(time.Minute, event.Bounce, "Permanent"),
			feedback(time.Minute, event.Delivery, ""),
			feedback(time.Minute, event.Delivery, "", withIP("203.0.113.7")),
		} {
			if set := observe(t, c, ev); i == 4 {
				want(t, "feedback with an IP", set.IP, map[string]any{"sends_1h": int64(4)})
			}
		}
		set := observe(t, c, feedback(2*time.Minute, event.Complaint, ""))
		want(t, "account", set.Account, map[string]any{
			"sends_24h":            int64(4),
			"bounces_24h":          int64(3),
			"hard_bounces_24h":     int64(2),
			"complaints_24h":       int64(1),
			"deliveries_24h":       int64(2),
			"bounce_rate_24h":      0.75,
			"hard_bounce_rate_24h": 0.5,
			"complaint_rate_24h":   0.25,
		})
		want(t, "domain", set.Domain, map[string]any{"complaints_24h": int64(1), "sends_1h": int64(4)})

		set = observe(t, c, feedback(day+3*time.Minute, event.Complaint, ""))
		want(t, "a day later", set.Account, map[string]any{
			"sends_24h": int64(0), "bounces_24h": int64(0), "complaints_24h": int64(1), "complaint_rate_24h": 1.0,
		})
	})
}

func TestRatesWithZeroSends(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		set := observe(t, c, accountEvent(0, "login"))
		want(t, "no sends, no feedback", set.Account, map[string]any{
			"bounce_rate_24h": 0.0, "hard_bounce_rate_24h": 0.0, "complaint_rate_24h": 0.0,
			"hourly_baseline_7d": 0.0, "volume_ratio_1h": 0.0,
		})
		for range 3 {
			set = observe(t, c, feedback(time.Minute, event.Bounce, "permanent"))
		}
		want(t, "bounces without sends", set.Account, map[string]any{
			"bounces_24h": int64(3), "bounce_rate_24h": 1.0, "hard_bounce_rate_24h": 1.0, "complaint_rate_24h": 0.0,
		})
	})
}

func TestVolumeRatio(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		set := observe(t, c, send(0))
		want(t, "first send", set.Account, map[string]any{"hourly_baseline_7d": 1.0 / 168, "volume_ratio_1h": 1.0})
		for i := 1; i < 200; i++ {
			set = observe(t, c, send(time.Duration(i)*time.Millisecond))
		}
		if got := set.Account["hourly_baseline_7d"].(float64); math.Abs(got-200.0/168) > 1e-9 {
			t.Errorf("hourly_baseline_7d = %v, want %v", got, 200.0/168)
		}
		if got := set.Account["volume_ratio_1h"].(float64); math.Abs(got-168) > 1e-9 {
			t.Errorf("volume_ratio_1h = %v, want 168", got)
		}
	})
}

func TestAccountAge(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		cases := []struct {
			name string
			ev   event.Event
			want float64
		}{
			{"first event", send(0, withAccount("a")), 0},
			{"since first seen", send(5*time.Hour, withAccount("a")), 5},
			{"created at, from an account event", accountEvent(time.Hour, "login", withAccount("b"), withCreatedAt(t0.Add(-48*time.Hour))), 49},
			{"created at, remembered", send(2*time.Hour, withAccount("b")), 50},
			{"created at, corrected", accountEvent(3*time.Hour, "login", withAccount("b"), withCreatedAt(t0)), 3},
			{"created at on a send", send(30*time.Minute, withAccount("c"), withCreatedAt(t0)), 0.5},
			{"created at in the future", send(0, withAccount("d"), withCreatedAt(t0.Add(10*time.Hour))), 0},
			{"later event seen first", send(5*time.Hour, withAccount("e")), 0},
			{"earlier event seen later", send(time.Hour, withAccount("e")), 0},
			{"first seen is the earliest", send(6*time.Hour, withAccount("e")), 5},
			{"millisecond precision, first", send(500*time.Microsecond, withAccount("f")), (500 * time.Microsecond).Hours()},
			{"millisecond precision, later", send(time.Hour, withAccount("f")), 1},
		}
		for _, tc := range cases {
			want(t, tc.name, observe(t, c, tc.ev).Account, map[string]any{"age_hours": tc.want})
		}
	})
}

func TestNewIP(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		cases := []struct {
			name         string
			ev           event.Event
			account, key any // nil means absent
		}{
			{"first send", send(0, withIP("203.0.113.1")), true, true},
			{"same IP", send(time.Hour, withIP("203.0.113.1")), false, false},
			{"another IP", send(2*time.Hour, withIP("203.0.113.2")), true, true},
			{"known to the account, new to the key", send(3*time.Hour, withIP("203.0.113.1"), withKey("key-2")), false, true},
			{"IPv6 spelled two ways, first", send(4*time.Hour, withIP("2001:DB8::1")), true, true},
			{"IPv6 spelled two ways, second", send(5*time.Hour, withIP("2001:db8:0:0::1")), false, false},
			{"IPv4-mapped IPv6", send(6*time.Hour, withIP("::ffff:203.0.113.1")), false, false},
			{"login from a new IP", accountEvent(7*time.Hour, "login", withIP("198.51.100.1"), withKey("key-1")), true, true},
			{"logins do not record IPs", send(8*time.Hour, withIP("198.51.100.1")), true, true},
			{"no IP", send(9*time.Hour, withIP("")), nil, nil},
			{"30 days, first", send(10*time.Hour, withAccount("x"), withKey("kx")), true, true},
			{"just under 30 days, first", send(10*time.Hour, withAccount("y"), withKey("ky")), true, true},
			{"just under 30 days later", send(10*time.Hour+30*day-time.Millisecond, withAccount("y"), withKey("ky")), false, false},
			{"30 days later", send(10*time.Hour+30*day, withAccount("x"), withKey("kx")), true, true},
		}
		for _, tc := range cases {
			set := observe(t, c, tc.ev)
			for _, m := range []struct {
				label string
				got   map[string]any
				want  any
			}{{"account", set.Account, tc.account}, {"key", set.Key, tc.key}} {
				got, ok := m.got["new_ip"]
				if tc.account == nil && ok {
					t.Errorf("%s: %s.new_ip = %v, want absent", tc.name, m.label, got)
				} else if tc.account != nil && got != m.want {
					t.Errorf("%s: %s.new_ip = %v, want %v", tc.name, m.label, got, m.want)
				}
			}
		}
	})
}

func TestKeySignals(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		ctx := context.Background()
		set := observe(t, c, accountEvent(0, "api_key_created", withKey("k")))
		want(t, "created", set.Key, map[string]any{"age_hours": 0.0, "sends_1h": int64(0), "leaked": false})

		observe(t, c, send(0, withKey("k"), withIP("203.0.113.1")))
		observe(t, c, send(10*time.Minute, withKey("k"), withIP("203.0.113.2")))
		set = observe(t, c, send(65*time.Minute, withKey("k"), withIP("203.0.113.3")))
		want(t, "after three sends", set.Key, map[string]any{
			"sends_1m": int64(1), "sends_1h": int64(2),
			"distinct_ips_1h": int64(2), "distinct_ips_24h": int64(3),
			"age_hours": (65 * time.Minute).Hours(), "leaked": false,
		})

		if err := c.MarkLeaked(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		set = observe(t, c, send(2*time.Hour, withKey("k")))
		want(t, "after MarkLeaked", set.Key, map[string]any{"leaked": true})
		set = observe(t, c, send(2*time.Hour, withKey("other")))
		want(t, "another key", set.Key, map[string]any{"leaked": false})

		leak := event.Event{Type: event.KeyLeak, Time: t0.Add(3 * time.Hour), APIKeyID: "leaky"}
		set = observe(t, c, leak)
		want(t, "key_leak event", set.Key, map[string]any{"leaked": true, "sends_1h": int64(0)})
		set = observe(t, c, send(4*time.Hour, withKey("leaky")))
		want(t, "after key_leak", set.Key, map[string]any{"leaked": true, "sends_1h": int64(1)})

		if err := c.MarkLeaked(ctx, ""); err == nil {
			t.Error("MarkLeaked accepted an empty key id")
		}
	})
}

func TestIPSignals(t *testing.T) {
	const ip = "198.51.100.9"
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		observe(t, c, send(0, withIP(ip), withAccount("a1"), withKey("k1")))
		observe(t, c, send(10*time.Second, withIP(ip), withAccount("a2"), withKey("k2")))
		set := observe(t, c, send(20*time.Second, withIP(ip), withAccount("a1"), withKey("k3")))
		want(t, "after sends", set.IP, map[string]any{
			"sends_1m": int64(3), "sends_1h": int64(3), "distinct_accounts_24h": int64(2),
			"distinct_keys_24h": int64(3), "signups_24h": int64(0),
		})

		observe(t, c, accountEvent(30*time.Second, "signup", withIP(ip), withAccount("a3")))
		observe(t, c, accountEvent(40*time.Second, "signup", withIP(ip), withAccount("a4")))
		set = observe(t, c, accountEvent(50*time.Second, "login", withIP(ip), withAccount("a1")))
		want(t, "after signups", set.IP, map[string]any{
			"sends_1m": int64(3), "signups_24h": int64(2), "distinct_accounts_24h": int64(2),
		})

		observe(t, c, accountEvent(day+40*time.Second, "signup", withIP(ip), withAccount("a5")))
		set = observe(t, c, accountEvent(day+time.Minute, "login", withIP(ip), withAccount("a5")))
		want(t, "a day later", set.IP, map[string]any{
			"sends_1m": int64(0), "sends_1h": int64(0), "signups_24h": int64(1), "distinct_accounts_24h": int64(0),
		})
	})
}

func TestDomainSignals(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		observe(t, c, send(0, withAccount("a1")))
		observe(t, c, send(time.Minute, withAccount("a2")))
		set := observe(t, c, send(2*time.Minute, withAccount("a1"), withFrom("Sales <SALES@Sender.Example>")))
		want(t, "after sends", set.Domain, map[string]any{
			"sends_1h": int64(3), "distinct_accounts_24h": int64(2), "complaints_24h": int64(0),
		})
		set = observe(t, c, feedback(3*time.Minute, event.Complaint, "", withAccount("a1")))
		want(t, "after a complaint", set.Domain, map[string]any{"sends_1h": int64(3), "complaints_24h": int64(1)})

		set = observe(t, c, feedback(4*time.Minute, event.Complaint, "", withAccount("a1"), withFrom("")))
		if set.Domain != nil {
			t.Errorf("feedback without From has domain signals %v", set.Domain)
		}
		want(t, "account of a feedback without From", set.Account, map[string]any{"complaints_24h": int64(2)})
		set = observe(t, c, send(5*time.Minute, withFrom("no-domain")))
		if set.Domain != nil {
			t.Errorf("From without a domain has domain signals %v", set.Domain)
		}
	})
}

func TestMapPresence(t *testing.T) {
	cases := []struct {
		name                     string
		ev                       event.Event
		account, key, ip, domain bool
	}{
		{"complete send", send(0), true, true, true, true},
		{"no key", send(0, withKey("")), true, false, true, true},
		{"no IP", send(0, withIP("")), true, true, false, true},
		{"no sender domain", send(0, withFrom("")), true, true, true, false},
		{"key_leak without account", event.Event{Type: event.KeyLeak, Time: t0, APIKeyID: "k"}, false, true, false, false},
	}
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		for _, tc := range cases {
			set := observe(t, c, tc.ev)
			for _, m := range []struct {
				label string
				got   map[string]any
				want  bool
			}{{"account", set.Account, tc.account}, {"key", set.Key, tc.key}, {"ip", set.IP, tc.ip}, {"domain", set.Domain, tc.domain}} {
				if (m.got != nil) != m.want {
					t.Errorf("%s: %s present = %v, want %v", tc.name, m.label, m.got != nil, m.want)
				}
			}
			if set.Event == nil {
				t.Errorf("%s: event signals absent", tc.name)
			}
		}
	})
}

var errBoom = errors.New("boom")

// failingStore fails every batch.
type failingStore struct{}

func (failingStore) Do(context.Context, *store.Batch) error { return errBoom }
func (failingStore) Close() error                           { return errBoom }

// blockingStore answers only when the context ends.
type blockingStore struct{}

func (blockingStore) Do(ctx context.Context, _ *store.Batch) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blockingStore) Close() error { return nil }

func TestObserveWhenTheStoreFails(t *testing.T) {
	ev := send(0)
	healthy := signal.NewCatalog(store.NewMemory(), signal.Options{})
	defer healthy.Close()
	wantEvent := observe(t, healthy, ev).Event

	check := func(t *testing.T, set signal.Set, err, wantErr error) {
		t.Helper()
		if !errors.Is(err, wantErr) {
			t.Errorf("error = %v, want %v", err, wantErr)
		}
		if !reflect.DeepEqual(set.Event, wantEvent) {
			t.Errorf("event signals = %v, want %v", set.Event, wantEvent)
		}
		if set.Account != nil || set.Key != nil || set.IP != nil || set.Domain != nil {
			t.Errorf("store-backed signals present after a failure: %+v", set)
		}
	}

	t.Run("store error", func(t *testing.T) {
		c := signal.NewCatalog(failingStore{}, signal.Options{})
		set, err := c.Observe(context.Background(), ev)
		check(t, set, err, errBoom)
		if err := c.MarkLeaked(context.Background(), "k"); !errors.Is(err, errBoom) {
			t.Errorf("MarkLeaked error = %v, want %v", err, errBoom)
		}
		if err := c.Close(); !errors.Is(err, errBoom) {
			t.Errorf("Close error = %v, want the store's", err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		c := signal.NewCatalog(blockingStore{}, signal.Options{})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		set, err := c.Observe(ctx, ev)
		check(t, set, err, context.DeadlineExceeded)
	})
	for _, be := range backends {
		t.Run("canceled context, "+be.name, func(t *testing.T) {
			c := signal.NewCatalog(be.new(t), signal.Options{})
			defer c.Close()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			set, err := c.Observe(ctx, ev)
			check(t, set, err, context.Canceled)
		})
	}
	t.Run("no time", func(t *testing.T) {
		c := signal.NewCatalog(store.NewMemory(), signal.Options{})
		defer c.Close()
		noTime := ev
		noTime.Time = time.Time{}
		set, err := c.Observe(context.Background(), noTime)
		if err == nil || !strings.Contains(err.Error(), "time") {
			t.Errorf("error = %v, want one about the missing time", err)
		}
		if set.Event == nil || set.Account != nil {
			t.Errorf("set = %+v, want only event signals", set)
		}
	})
}

// randomEvents returns n events of every type, in time order, drawn from a
// few accounts, keys, IPs and domains so the counters overlap.
func randomEvents(n int) []event.Event {
	r := rand.New(rand.NewPCG(1, 2))
	pick := func(xs ...string) string { return xs[r.IntN(len(xs))] }
	accounts := []string{"a1", "a2", "a3", "a4", "a5"}
	keys := []string{"", "k1", "k2", "k3", "k4", "k5", "k6"}
	ips := []string{"", "203.0.113.1", "203.0.113.2", "198.51.100.7", "2001:db8::1", "2001:DB8::2"}
	froms := []string{"", "news@one.example", "info@two.example", "Team <team@three.example>"}
	rcpts := []string{"a@m1.example", "b@m2.example", "c@m3.example", "d@m1.example", "e@m4.example", "f@m5.example"}
	at := t0
	events := make([]event.Event, 0, n)
	for range n {
		at = at.Add(time.Duration(r.Int64N(int64(time.Hour))))
		ev := event.Event{Time: at, AccountID: pick(accounts...), APIKeyID: pick(keys...), IP: pick(ips...), From: pick(froms...)}
		switch p := r.IntN(100); {
		case p < 70:
			ev.Type = event.Send
			for range 1 + r.IntN(4) {
				ev.To = append(ev.To, pick(rcpts...))
			}
		case p < 85:
			ev.Type = event.Feedback
			ev.IP = ""
			ev.Feedback = &event.FeedbackInfo{
				Kind:       event.FeedbackKind(pick("bounce", "complaint", "delivery")),
				BounceType: pick("permanent", "transient"),
			}
		case p < 95:
			ev.Type = event.Account
			ev.Account = &event.AccountInfo{Action: pick("signup", "login", "api_key_created")}
			if r.IntN(3) == 0 {
				created := t0.Add(-time.Duration(r.Int64N(int64(week))))
				ev.Account.CreatedAt = &created
			}
		default:
			ev.Type = event.KeyLeak
			ev.APIKeyID = pick(keys[1:]...)
		}
		events = append(events, ev)
	}
	return events
}

// TestReplayReproducesSignals replays the same events into fresh stores of
// each backend and expects the same signals every time: windows follow event
// time, not the wall clock.
func TestReplayReproducesSignals(t *testing.T) {
	events := randomEvents(400)
	replay := func(s store.Store) []signal.Set {
		c := signal.NewCatalog(s, signal.Options{})
		defer c.Close()
		sets := make([]signal.Set, len(events))
		for i, ev := range events {
			sets[i] = observe(t, c, ev)
		}
		return sets
	}
	first := replay(store.NewMemory())
	runs := map[string][]signal.Set{
		"memory again": replay(store.NewMemory()),
		"redis":        replay(backends[1].new(t)),
	}
	for name, sets := range runs {
		for i := range sets {
			if !reflect.DeepEqual(sets[i], first[i]) {
				t.Errorf("%s: event %d (%s at %v) differs\n got %+v\nwant %+v",
					name, i, events[i].Type, events[i].Time.Sub(t0), sets[i], first[i])
				break
			}
		}
	}
}
