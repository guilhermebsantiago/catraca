package engine

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// crockford is the base32 alphabet of ULIDs: no I, L, O or U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// idSource makes ULIDs (github.com/ulid/spec): 48 bits of Unix milliseconds
// followed by 80 random bits, as 26 base32 characters, so ids sort by time.
// Within one millisecond the random part is incremented instead of redrawn,
// so the ids of one engine are strictly increasing even when the clock
// stalls or steps back. The zero value is ready to use.
type idSource struct {
	mu     sync.Mutex
	ms     uint64
	randHi uint16
	randLo uint64
}

func (s *idSource) next(t time.Time) string {
	ms := uint64(max(t.UnixMilli(), 0))
	s.mu.Lock()
	if ms > s.ms {
		var b [10]byte
		_, _ = rand.Read(b[:])
		s.ms = ms
		s.randHi = binary.BigEndian.Uint16(b[:2])
		s.randLo = binary.BigEndian.Uint64(b[2:])
	} else {
		s.randLo++
		if s.randLo == 0 {
			s.randHi++
			if s.randHi == 0 {
				// 2^80 ids in one millisecond: borrow the next one.
				s.ms++
			}
		}
	}
	hi := s.ms<<16 | uint64(s.randHi)
	lo := s.randLo
	s.mu.Unlock()
	return encodeULID(hi, lo)
}

// encodeULID writes the 128-bit value hi:lo as 26 base32 digits, the first
// of which carries only 3 bits.
func encodeULID(hi, lo uint64) string {
	var dst [26]byte
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(dst[:])
}
