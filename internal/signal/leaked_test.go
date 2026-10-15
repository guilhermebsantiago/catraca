package signal

import (
	"fmt"
	"sync"
	"testing"
)

func TestLeakedKeysForgetTheLeastRecentlySeen(t *testing.T) {
	s := newLeakedKeys(3)
	for _, id := range []string{"a", "b", "c", "a", "d"} {
		s.add(id)
	}
	// "a" was seen again before "d" arrived, so "b" is the one forgotten.
	for id, want := range map[string]bool{"a": true, "b": false, "c": true, "d": true, "e": false} {
		if got := s.has(id); got != want {
			t.Errorf("has(%q) = %v, want %v", id, got, want)
		}
	}
	if len(s.ids) != 3 || s.order.Len() != 3 {
		t.Errorf("size = %d/%d, want 3", len(s.ids), s.order.Len())
	}
}

func TestLeakedKeysStayBounded(t *testing.T) {
	s := newLeakedKeys(maxLeakedKeys)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range maxLeakedKeys {
				s.add(fmt.Sprintf("key-%d-%d", w, i))
				s.has(fmt.Sprintf("key-%d-%d", w, i/2))
			}
		})
	}
	wg.Wait()
	if len(s.ids) != maxLeakedKeys || s.order.Len() != maxLeakedKeys {
		t.Errorf("size = %d/%d, want the cap %d", len(s.ids), s.order.Len(), maxLeakedKeys)
	}
}
