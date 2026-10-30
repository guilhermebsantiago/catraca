package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// benchDecisions records n decisions on db, a tenth of them matched by a
// rule, one millisecond apart from t0, and waits until they are written.
func benchDecisions(b *testing.B, db *DB, n int) {
	b.Helper()
	ctx := context.Background()
	ev := sendEvent("bench")
	for i := range n {
		var enforced []string
		if i%10 == 0 {
			enforced = []string{"a"}
		}
		db.Record(ctx, ev, newDecision(fmt.Sprintf("d%08d", i), t0.Add(time.Duration(i)*time.Millisecond), enforced, nil))
		// Stay under the buffer, which would drop the rest.
		if i%4096 == 4095 {
			if err := db.Flush(ctx); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := db.Flush(ctx); err != nil {
		b.Fatal(err)
	}
}

func benchDB(b *testing.B, opts Options) *DB {
	b.Helper()
	db, err := Open(context.Background(), "sqlite:"+filepath.Join(b.TempDir(), "audit.db"), opts)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close(context.Background()) })
	return db
}

// BenchmarkRecordSQLite measures the writer: decisions recorded and written
// to a SQLite file, per second.
func BenchmarkRecordSQLite(b *testing.B) {
	const n = 20000
	for b.Loop() {
		b.StopTimer()
		db := benchDB(b, Options{})
		b.StartTimer()
		benchDecisions(b, db, n)
	}
	b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "decisions/s")
}

// BenchmarkPruneSQLite measures retention: expired decisions deleted from a
// SQLite file per second, pauses included, by rows per statement.
func BenchmarkPruneSQLite(b *testing.B) {
	const n = 50000
	for _, batch := range []int{pruneBatch, pruneBatchPostgres} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			for b.Loop() {
				b.StopTimer()
				db := benchDB(b, Options{Retention: 48 * time.Hour, PruneBatch: batch})
				db.stopPruning()
				<-db.pruned
				benchDecisions(b, db, n)
				b.StartTimer()
				if err := db.prune(context.Background(), t0.Add(5*24*time.Hour)); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(n*b.N)/b.Elapsed().Seconds(), "decisions/s")
		})
	}
}
