package signal_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
	"github.com/guilhermebsantiago/catraca/internal/store"
	"github.com/guilhermebsantiago/catraca/internal/store/storetest"
)

func withRecipient(r string) func(*event.Event) {
	return func(e *event.Event) { e.Feedback.Recipient = r }
}

// suppressed returns event.suppressed_recipients and event.suppressed_ratio.
func suppressed(t *testing.T, set signal.Set) (int64, float64) {
	t.Helper()
	n, ok1 := set.Event["suppressed_recipients"].(int64)
	r, ok2 := set.Event["suppressed_ratio"].(float64)
	if !ok1 || !ok2 {
		t.Fatalf("suppressed signals missing or mistyped: %v, %v", set.Event["suppressed_recipients"], set.Event["suppressed_ratio"])
	}
	return n, r
}

func TestRecipientMemory(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		// acct-1's hard bounce and complaint are remembered for every
		// account; its soft bounce and delivery are not.
		observe(t, c, feedback(0, event.Bounce, "Permanent", withRecipient("gone@inbox.example")))
		observe(t, c, feedback(0, event.Complaint, "", withRecipient("angry@inbox.example")))
		observe(t, c, feedback(0, event.Bounce, "transient", withRecipient("full@inbox.example")))
		observe(t, c, feedback(0, event.Delivery, "", withRecipient("fine@inbox.example")))
		observe(t, c, feedback(0, event.Bounce, "permanent")) // no recipient

		other := withAccount("acct-2")
		cases := []struct {
			name   string
			offset time.Duration
			to     []string
			n      int64
			ratio  float64
		}{
			{"none", time.Hour, []string{"new@inbox.example", "full@inbox.example", "fine@inbox.example"}, 0, 0},
			{"hard bounce", time.Hour, []string{"gone@inbox.example", "new@inbox.example"}, 1, 0.5},
			{"both, spelled differently", time.Hour, []string{" GONE@Inbox.Example", "Angry Person <angry@inbox.example>", "x@inbox.example", "y@inbox.example"}, 2, 0.5},
			{"repeated address counts once", time.Hour, []string{"gone@inbox.example", "Gone@inbox.example", "new@inbox.example"}, 1, 0.5},
			{"no addresses", time.Hour, []string{"no-domain"}, 0, 0},
			{"no recipients", time.Hour, nil, 0, 0},
			{"within the memory", 30*day - time.Second, []string{"gone@inbox.example"}, 1, 1},
			{"forgotten", 30 * day, []string{"gone@inbox.example"}, 0, 0},
		}
		for _, tc := range cases {
			set := observe(t, c, send(tc.offset, other, withTo(tc.to...)))
			if n, r := suppressed(t, set); n != tc.n || r != tc.ratio {
				t.Errorf("%s: suppressed = %d, ratio %v; want %d, %v", tc.name, n, r, tc.n, tc.ratio)
			}
		}

		// A later bounce renews the memory.
		observe(t, c, feedback(29*day, event.Bounce, "permanent", withRecipient("gone@inbox.example")))
		if n, _ := suppressed(t, observe(t, c, send(58*day, other, withTo("gone@inbox.example")))); n != 1 {
			t.Errorf("after a second bounce: suppressed = %d, want 1", n)
		}
	})
}

func TestRecipientMemoryCap(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		to := make([]string, event.MaxRecipients)
		for i := range to {
			to[i] = fmt.Sprintf("r%d@list.example", i)
			if i%2 == 0 {
				observe(t, c, feedback(0, event.Bounce, "permanent", withRecipient(to[i])))
			}
		}
		set := observe(t, c, send(time.Hour, withTo(to...)))
		n, r := suppressed(t, set)
		if n < 25 || n > 75 || r != float64(n)/signal.MaxCheckedRecipients {
			t.Errorf("half of %d recipients suppressed: suppressed = %d, ratio %v; want about %d of %d checked",
				len(to), n, r, signal.MaxCheckedRecipients/2, signal.MaxCheckedRecipients)
		}
		// The same recipients in another order check the same ones.
		rev := make([]string, len(to))
		for i, a := range to {
			rev[len(to)-1-i] = a
		}
		if n2, _ := suppressed(t, observe(t, c, send(time.Hour, withTo(rev...)))); n2 != n {
			t.Errorf("reordered recipients: suppressed = %d, want %d", n2, n)
		}
	})
}

func TestRecipientMemoryOptions(t *testing.T) {
	bounce := feedback(0, event.Bounce, "permanent", withRecipient("gone@inbox.example"))
	later := send(time.Hour, withTo("gone@inbox.example"))

	t.Run("off", func(t *testing.T) {
		c := signal.NewCatalog(store.NewMemory(), signal.Options{RecipientMemory: -1})
		defer c.Close()
		observe(t, c, bounce)
		set := observe(t, c, later)
		if _, ok := set.Event["suppressed_recipients"]; ok {
			t.Errorf("suppressed_recipients present with the memory off: %v", set.Event)
		}
	})
	t.Run("short memory", func(t *testing.T) {
		c := signal.NewCatalog(store.NewMemory(), signal.Options{RecipientMemory: 30 * time.Minute})
		defer c.Close()
		observe(t, c, bounce)
		if n, _ := suppressed(t, observe(t, c, later)); n != 0 {
			t.Errorf("suppressed = %d an hour after a bounce with a 30m memory, want 0", n)
		}
	})
	t.Run("hash key", func(t *testing.T) {
		// Two catalogs with different keys on one store do not see each
		// other's addresses; with the same key they do.
		s := store.NewMemory()
		a := signal.NewCatalog(s, signal.Options{RecipientHashKey: []byte("key-a")})
		b := signal.NewCatalog(s, signal.Options{RecipientHashKey: []byte("key-b")})
		a2 := signal.NewCatalog(s, signal.Options{RecipientHashKey: []byte("key-a")})
		defer a.Close()
		observe(t, a, bounce)
		if n, _ := suppressed(t, observe(t, b, later)); n != 0 {
			t.Errorf("another key: suppressed = %d, want 0", n)
		}
		if n, _ := suppressed(t, observe(t, a2, later)); n != 1 {
			t.Errorf("the same key: suppressed = %d, want 1", n)
		}
	})
}

// TestRecipientMemoryStoresNoAddress checks that Redis holds digests, not
// the addresses or anything that contains them.
func TestRecipientMemoryStoresNoAddress(t *testing.T) {
	mr := storetest.Miniredis(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, ReadTimeout: storetest.MiniredisReadTimeout})
	defer client.Close()
	c := signal.NewCatalog(store.NewRedis(client, store.RedisOptions{}), signal.Options{RecipientHashKey: []byte("secret")})
	defer c.Close()
	ev := feedback(0, event.Complaint, "", withRecipient("victim@inbox.example"))
	ev.AccountID = ""
	ev.From = ""
	observe(t, c, ev)

	keys := mr.Keys()
	if len(keys) != 1 || !strings.HasPrefix(keys[0], store.DefaultPrefix+"s:recipient:suppressed:") {
		t.Fatalf("keys = %v, want one shard of the recipient memory", keys)
	}
	members, err := client.ZRange(context.Background(), keys[0], 0, -1).Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || len(members[0]) != 16 || strings.Contains(members[0], "victim") {
		t.Errorf("members = %q, want one 16-character digest", members)
	}
}

func TestRoleRecipients(t *testing.T) {
	ev := send(0, withTo(
		"info@shop.example", "Sales+EU@shop.example", "Support <support@shop.example>",
		"jane@shop.example", "info.jane@shop.example", "noreply@shop.example", "info", "@shop.example",
	))
	c := signal.NewCatalog(store.NewMemory(), signal.Options{})
	defer c.Close()
	if got := observe(t, c, ev).Event["role_recipients"]; got != int64(4) {
		t.Errorf("role_recipients = %v, want 4", got)
	}
}
