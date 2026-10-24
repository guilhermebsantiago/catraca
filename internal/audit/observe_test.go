package audit

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// batchWrites records what OnBatchWrite is told.
type batchWrites struct {
	mu     sync.Mutex
	writes []BatchWrite
	traced []bool
}

func (b *batchWrites) record(ctx context.Context, w BatchWrite) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writes = append(b.writes, w)
	b.traced = append(b.traced, trace.SpanContextFromContext(ctx).IsValid())
}

func TestBatchWritesAreReportedAndTraced(t *testing.T) {
	ctx := context.Background()
	var seen batchWrites
	sr := tracetest.NewSpanRecorder()
	db, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "audit.db"), Options{
		Logger:         slog.New(slog.DiscardHandler),
		OnBatchWrite:   seen.record,
		TracerProvider: sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)

	for _, id := range []string{"d1", "d2"} {
		ev := sendEvent(id)
		ev.AccountID = "acct_person_7"
		db.Record(ctx, ev, newDecision(id, t0, []string{"a"}, nil))
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// A row the database refuses makes its batch go one decision at a time.
	if _, err := db.SQL().ExecContext(ctx, `CREATE TRIGGER refuse_poison BEFORE INSERT ON decisions
WHEN NEW.account_id = 'poison' BEGIN SELECT RAISE(ABORT, 'poison row'); END`); err != nil {
		t.Fatal(err)
	}
	ev := sendEvent("d3")
	ev.AccountID = "poison"
	db.Record(ctx, ev, newDecision("d3", t0, []string{"a"}, nil))
	_ = db.Flush(ctx)

	seen.mu.Lock()
	defer seen.mu.Unlock()
	if len(seen.writes) != 2 {
		t.Fatalf("OnBatchWrite got %+v, want two batches", seen.writes)
	}
	if w := seen.writes[0]; w.Result != WriteOK || w.Decisions != 2 || w.Duration <= 0 {
		t.Errorf("first batch = %+v, want 2 decisions written", w)
	}
	if w := seen.writes[1]; w.Result != WriteRefused || w.Decisions != 1 {
		t.Errorf("second batch = %+v, want 1 decision refused", w)
	}
	if !seen.traced[0] || !seen.traced[1] {
		t.Error("OnBatchWrite did not get the batch's span")
	}

	spans := sr.Ended()
	if len(spans) != 2 {
		t.Fatalf("%d spans, want one per batch", len(spans))
	}
	for i, s := range spans {
		if s.Name() != "catraca.audit.write_batch" || s.Parent().IsValid() {
			t.Errorf("span %d: %q with parent %v, want a write_batch that starts a trace", i, s.Name(), s.Parent())
		}
		for _, kv := range s.Attributes() {
			if strings.Contains(kv.Value.String(), "acct_person_7") {
				t.Errorf("span %d: %s carries an account id", i, kv.Key)
			}
		}
	}
	if spans[1].Status().Description != "decisions were not written" {
		t.Errorf("refused batch span status = %+v", spans[1].Status())
	}
}
