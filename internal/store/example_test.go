package store_test

import (
	"context"
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/store"
)

func ExampleBatch() {
	s := store.NewMemory()
	defer s.Close()
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

	// Record one send and read the counters back, in one round trip.
	var b store.Batch
	seen := b.SeenWithin("account:seen_ips:42", "203.0.113.7", 30*24*time.Hour, at)
	b.Incr("account:sends:42", time.Hour, at, 1)
	b.AddDistinct("account:recipient_domains:42", "mail.example", time.Hour, at)
	b.MarkSeen("account:seen_ips:42", "203.0.113.7", at, 30*24*time.Hour)
	sends := b.Count("account:sends:42", time.Hour, at)
	domains := b.Distinct("account:recipient_domains:42", time.Hour, at)
	first := b.FirstSeen("account:first_seen:42", at, 365*24*time.Hour)
	if err := s.Do(context.Background(), &b); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(seen.Val(), sends.Val(), domains.Val(), first.Val().Format(time.RFC3339))
	// Output: false 1 1 2026-03-02T09:00:00Z
}
