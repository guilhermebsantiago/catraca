package audit

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// WriteResult is how an attempt to write a batch of decisions went. The
// values are few and fixed, so they can label a metric.
type WriteResult string

const (
	// WriteOK means the batch was written.
	WriteOK WriteResult = "ok"
	// WriteRefused means the database refused a value in the batch; its
	// decisions are written one at a time next.
	WriteRefused WriteResult = "refused"
	// WriteFailed means the database could not take the write: it is down,
	// locked, full or read-only, or the attempt timed out.
	WriteFailed WriteResult = "error"
)

// BatchWrite describes one attempt to write a batch of decisions, for
// Options.OnBatchWrite.
type BatchWrite struct {
	// Decisions is how many decisions the batch holds.
	Decisions int
	// Duration is how long the attempt took, its transaction included.
	Duration time.Duration
	Result   WriteResult
}

// tracerName is the instrumentation scope of the audit log's spans.
const tracerName = "github.com/guilhermebsantiago/catraca/internal/audit"

// traceBatch starts the span of writing a batch of n decisions, with
// tracing on, and returns its context and the function that ends it with
// the write's error. A batch holds decisions from many requests, so its
// span starts a trace of its own.
func (db *DB) traceBatch(n int) (context.Context, func(error)) {
	if db.tracer == nil {
		return db.writeCtx, func(error) {}
	}
	system := db.dialect.name
	if system == "postgres" {
		system = "postgresql" // as OpenTelemetry names it
	}
	ctx, span := db.tracer.Start(db.writeCtx, "catraca.audit.write_batch", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.Int("catraca.audit.decisions", n), attribute.String("db.system.name", system)))
	return ctx, func(err error) {
		if err != nil {
			// The database's error may quote a value of a decision.
			span.SetStatus(codes.Error, "decisions were not written")
		}
		span.End()
	}
}

// observeWrite reports an attempt at writing a batch to OnBatchWrite.
func (db *DB) observeWrite(ctx context.Context, n int, took time.Duration, err error) {
	w := BatchWrite{Decisions: n, Duration: took, Result: WriteOK}
	switch {
	case err == nil:
	case db.dialect.refused(err):
		w.Result = WriteRefused
	default:
		w.Result = WriteFailed
	}
	db.opts.OnBatchWrite(ctx, w)
}
