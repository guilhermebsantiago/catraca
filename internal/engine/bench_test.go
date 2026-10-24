package engine

import (
	"context"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/rules"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// benchSignals is a healthy, established sender: every rule of the default
// ruleset is evaluated in full and none matches, the common case in
// production.
func benchSignals() signal.Set {
	return signal.Set{
		Event: map[string]any{
			"type": "send", "account_id": "acct_1", "api_key_id": "key_1", "ip": "203.0.113.10",
			"from_domain": "example.com", "recipients": int64(1), "to_domains": []string{"gmail.com"},
			"link_domains": []string{"example.com"}, "links": int64(1), "subject_length": int64(32),
			"feedback_kind": "", "bounce_type": "", "account_action": "", "attributes": map[string]string{},
		},
		Account: map[string]any{
			"sends_1m": int64(2), "sends_1h": int64(40), "sends_24h": int64(900), "sends_7d": int64(6000),
			"recipients_1h": int64(40), "recipients_24h": int64(900),
			"distinct_recipient_domains_1h": int64(12), "distinct_recipient_domains_24h": int64(60),
			"distinct_ips_24h": int64(2), "distinct_keys_24h": int64(1),
			"bounces_24h": int64(4), "hard_bounces_24h": int64(2), "complaints_24h": int64(0), "deliveries_24h": int64(890),
			"bounce_rate_24h": 0.0044, "hard_bounce_rate_24h": 0.0022, "complaint_rate_24h": 0.0,
			"age_hours": 4000.0, "hourly_baseline_7d": 35.7, "volume_ratio_1h": 1.12, "new_ip": false,
			"ip_sends_24h": int64(450), "ip_sends_7d": int64(3000), "recent_ip": false,
		},
		Key: map[string]any{
			"sends_1m": int64(2), "sends_1h": int64(40), "distinct_ips_1h": int64(1), "distinct_ips_24h": int64(2),
			"new_ip": false, "age_hours": 3000.0, "leaked": false,
		},
		IP: map[string]any{
			"sends_1m": int64(2), "sends_1h": int64(40), "distinct_accounts_24h": int64(1),
			"distinct_keys_24h": int64(1), "signups_24h": int64(0),
		},
		Domain: map[string]any{"sends_1h": int64(40), "distinct_accounts_24h": int64(1), "complaints_24h": int64(0)},
	}
}

// BenchmarkDecide measures the engine's own cost per decision, with an
// in-memory catalog that answers instantly and the default ruleset.
func BenchmarkDecide(b *testing.B) {
	eng, ev := benchEngine(b)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := eng.Decide(ctx, ev); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecideParallel is BenchmarkDecide from GOMAXPROCS goroutines, to
// catch contention on shared state such as the id source and the metrics.
func BenchmarkDecideParallel(b *testing.B) {
	eng, ev := benchEngine(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := eng.Decide(ctx, ev); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkDecideTraced is BenchmarkDecide with tracing on and every trace
// sampled, the most tracing can cost, but with no exporter: the cost of the
// spans themselves, not of sending them.
func BenchmarkDecideTraced(b *testing.B) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	eng, ev := benchEngine(b, func(o *Options) { o.TracerProvider = tp })
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := eng.Decide(ctx, ev); err != nil {
			b.Fatal(err)
		}
	}
}

func benchEngine(b *testing.B, mod ...func(*Options)) (*Engine, event.Event) {
	b.Helper()
	rs, err := rules.LoadFile("../../rules/default.yaml")
	if err != nil {
		b.Fatal(err)
	}
	opts := Options{
		Catalog: &fakeCatalog{set: benchSignals()},
		Rules:   rules.NewHolder(rs),
	}
	for _, m := range mod {
		m(&opts)
	}
	eng, err := New(opts)
	if err != nil {
		b.Fatal(err)
	}
	ev := event.Event{
		Type: event.Send, AccountID: "acct_1", APIKeyID: "key_1", IP: "203.0.113.10",
		From: "news@example.com", To: []string{"someone@gmail.com"}, Subject: "Your weekly summary",
		Links: []string{"https://example.com/summary"},
	}
	return eng, ev
}
