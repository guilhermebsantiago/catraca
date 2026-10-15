package signal_test

import (
	"context"
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

func ExampleNewCatalog() {
	c := signal.NewCatalog(store.NewMemory(), signal.Options{})
	defer c.Close()

	ev := event.Event{
		Type:      event.Send,
		Time:      time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC),
		AccountID: "acct-42",
		IP:        "203.0.113.7",
		From:      "hello@shop.example",
		To:        []string{"ana@mail.example"},
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.7", "198.51.100.1"} {
		ev.Time = ev.Time.Add(time.Second)
		ev.IP = ip
		set, err := c.Observe(context.Background(), ev)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(set.Account["sends_1m"], set.Account["new_ip"], set.Domain["sends_1h"])
	}
	// Output:
	// 1 true 1
	// 2 false 2
	// 3 true 3
}
