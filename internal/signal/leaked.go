package signal

import (
	"container/list"
	"sync"
)

// maxLeakedKeys bounds how many leaked keys a catalog remembers in memory,
// about 1.5 MB at the cap. The cap is safe because the set is only a
// fallback for store outages and the store keeps every leaked key: reported
// keys are rare and usually revoked soon after, so few processes come near
// it, and past it the key forgotten is the one least recently seen, whose
// sends are then allowed during an outage just as on a replica that never
// saw it. It also bounds the memory a flood of key_leak events can take.
const maxLeakedKeys = 10_000

// leakedKeys are the API keys this process knows were reported leaked,
// because it marked them or read them from the store, so that key.leaked
// still holds for them while the store is down. Safe for concurrent use.
type leakedKeys struct {
	mu    sync.RWMutex
	limit int
	ids   map[string]*list.Element
	order list.List // of string ids, least recently seen first
}

func newLeakedKeys(limit int) *leakedKeys {
	return &leakedKeys{limit: limit, ids: make(map[string]*list.Element)}
}

// add remembers id, or marks it as just seen when it is already known, and
// forgets the least recently seen key when the set is over its cap.
func (s *leakedKeys) add(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.ids[id]; ok {
		s.order.MoveToBack(e)
		return
	}
	s.ids[id] = s.order.PushBack(id)
	if s.order.Len() > s.limit {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		delete(s.ids, oldest.Value.(string))
	}
}

// has is called for every event with an API key, so it takes only the read
// lock.
func (s *leakedKeys) has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.ids[id]
	return ok
}
