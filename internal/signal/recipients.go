package signal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"slices"
	"strings"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

const (
	// DefaultRecipientMemory is the default for Options.RecipientMemory.
	DefaultRecipientMemory = 30 * day
	// MaxCheckedRecipients is the most recipients of one send checked
	// against the recipient memory. A send may carry event.MaxRecipients;
	// past this many, the ones checked are those whose hashes sort first,
	// so the same send always checks the same ones, and a sender who does
	// not know the hash key cannot choose which.
	MaxCheckedRecipients = 100
	// recipientShards is how many sets the recipient memory is split into,
	// by hash. On a Redis Cluster each is a key of its own, so the memory
	// spreads over that many hash slots, and a send makes at most that many
	// script calls more, whatever its recipients.
	recipientShards = 16
	// recipientHashBytes is how much of each address's HMAC the memory
	// keeps. 96 bits make a false match, which would count an address that
	// never bounced, unlikely while fewer than about 2^40 addresses are
	// remembered.
	recipientHashBytes = 12
)

// recipientDomain separates the recipient hashes from any other use of the
// key, and stands in for one when none is configured.
const recipientDomain = "catraca recipient memory v1"

// recipientKey is the key of one shard of the recipient memory.
func recipientKey(shard byte) string {
	return "recipient:suppressed:" + string("0123456789abcdef"[shard%recipientShards])
}

// recipientHash is the keyed digest the memory keeps instead of an address.
type recipientHash [recipientHashBytes]byte

func (h recipientHash) shard() byte { return h[recipientHashBytes-1] }

func (h recipientHash) member() string { return base64.RawURLEncoding.EncodeToString(h[:]) }

// recipientHasher hashes normalized addresses with HMAC-SHA-256. It is not
// safe for concurrent use; each Observe makes its own.
type recipientHasher struct {
	mac hash.Hash
	buf []byte
	sum []byte
}

func newRecipientHasher(key []byte) *recipientHasher {
	if len(key) == 0 {
		key = []byte(recipientDomain)
	}
	return &recipientHasher{mac: hmac.New(sha256.New, key), sum: make([]byte, 0, sha256.Size)}
}

// hash returns the digest of address, and false when it has no address to
// hash.
func (h *recipientHasher) hash(address string) (recipientHash, bool) {
	var out recipientHash
	address = normalizeRecipient(address)
	if address == "" {
		return out, false
	}
	h.buf = append(append(h.buf[:0], recipientDomain...), 0)
	h.buf = append(h.buf, address...)
	h.mac.Reset()
	h.mac.Write(h.buf)
	h.sum = h.mac.Sum(h.sum[:0])
	copy(out[:], h.sum)
	return out, true
}

// normalizeRecipient returns the bare address in "Name <user@example.com>",
// or the address as given, trimmed and lowercased; "" when it has no '@'.
// Mailbox providers treat local parts as case-insensitive, though RFC 5321
// does not, and the engine lowercases addresses before they get here.
// Provider-specific aliases (dots and +tags at Gmail) are left alone: they
// are separate addresses to every other provider.
func normalizeRecipient(address string) string {
	if i := strings.LastIndexByte(address, '<'); i >= 0 {
		if j := strings.IndexByte(address[i:], '>'); j > 0 {
			address = address[i+1 : i+j]
		}
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if strings.IndexByte(address, '@') <= 0 {
		return ""
	}
	return address
}

// suppressedReads are the recipient memory lookups of a send.
type suppressedReads struct {
	found []*store.BoolResult
}

// recipientMemory queues the recipient memory's writes and reads: a hard
// bounce or complaint remembers its recipient, and a send looks up at most
// MaxCheckedRecipients of its own. It returns nil when the memory is off.
func (c *catalog) recipientMemory(b *store.Batch, ev event.Event) *suppressedReads {
	if c.recipientMemoryTTL <= 0 {
		return nil
	}
	switch ev.Type {
	case event.Feedback:
		fb := ev.Feedback
		if fb == nil || !(fb.Kind == event.Complaint || fb.Kind == event.Bounce && strings.EqualFold(fb.BounceType, "permanent")) {
			break
		}
		if sum, ok := newRecipientHasher(c.recipientHashKey).hash(fb.Recipient); ok {
			b.MarkSeen(recipientKey(sum.shard()), sum.member(), ev.Time, c.recipientMemoryTTL)
		}
	case event.Send:
		r := &suppressedReads{}
		for _, sum := range checkedRecipients(newRecipientHasher(c.recipientHashKey), ev.To) {
			r.found = append(r.found, b.SeenWithin(recipientKey(sum.shard()), sum.member(), c.recipientMemoryTTL, ev.Time))
		}
		return r
	}
	return &suppressedReads{}
}

// checkedRecipients returns the distinct hashes of to, or, when there are
// more than MaxCheckedRecipients, the MaxCheckedRecipients that sort first.
func checkedRecipients(h *recipientHasher, to []string) []recipientHash {
	sums := make([]recipientHash, 0, len(to))
	for _, a := range to {
		if sum, ok := h.hash(a); ok {
			sums = append(sums, sum)
		}
	}
	cmp := func(a, b recipientHash) int { return bytes.Compare(a[:], b[:]) }
	slices.SortFunc(sums, cmp)
	sums = slices.Compact(sums)
	return sums[:min(len(sums), MaxCheckedRecipients)]
}

// addTo adds event.suppressed_recipients and event.suppressed_ratio to m.
func (r *suppressedReads) addTo(m map[string]any) {
	if r == nil {
		return
	}
	var n int64
	for _, f := range r.found {
		if f.Val() {
			n++
		}
	}
	m["suppressed_recipients"] = n
	m["suppressed_ratio"] = float64(n) / float64(max(len(r.found), 1))
}

// roleLocalParts are the local parts of role addresses: mailboxes of a
// function rather than a person, read by several people or none. Lists
// bought or scraped are full of them; people rarely sign up with one.
var roleLocalParts = map[string]bool{
	"abuse": true, "admin": true, "administrator": true, "billing": true,
	"contact": true, "enquiries": true, "help": true, "hello": true,
	"hostmaster": true, "info": true, "inquiries": true, "marketing": true,
	"no-reply": true, "noc": true, "noreply": true, "office": true,
	"postmaster": true, "privacy": true, "root": true, "sales": true,
	"security": true, "support": true, "webmaster": true,
}

// roleRecipients counts the addresses in to whose local part, before any
// +tag, is a role.
func roleRecipients(to []string) int64 {
	var n int64
	for _, a := range to {
		a = normalizeRecipient(a)
		at := strings.LastIndexByte(a, '@')
		if at <= 0 {
			continue
		}
		local, _, _ := strings.Cut(a[:at], "+")
		if roleLocalParts[local] {
			n++
		}
	}
	return n
}
