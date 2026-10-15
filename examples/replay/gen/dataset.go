package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/replay"
)

// seed fixes every random choice. Each scenario draws from its own stream,
// derived from the seed and the scenario's name, so changing one scenario
// leaves the others' events as they were.
const seed = 20261015

// start is the first instant of the dataset, a Tuesday; it spans days days.
var start = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

const days = 10

// day returns midnight UTC of day n, counting from 0.
func day(n int) time.Time { return start.AddDate(0, 0, n) }

// clock returns hh:mm UTC on day n.
func clock(n, hh, mm int) time.Time {
	return day(n).Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute)
}

// rng is SplitMix64. The generator does not use math/rand so that its output
// cannot change with the Go release that runs it.
type rng struct{ state uint64 }

func newRNG(name string) *rng {
	h := fnv.New64a()
	h.Write([]byte(name))
	return &rng{state: seed ^ h.Sum64()}
}

func (r *rng) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// intn returns an int in [0, n).
func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// between returns an int in [lo, hi].
func (r *rng) between(lo, hi int) int { return lo + r.intn(hi-lo+1) }

// float returns a float64 in [0, 1).
func (r *rng) float() float64 { return float64(r.next()>>11) * 0x1p-53 }

func (r *rng) chance(p float64) bool { return r.float() < p }

// within returns a duration in [0, d).
func (r *rng) within(d time.Duration) time.Duration {
	return time.Duration(r.next() % uint64(d))
}

// exp returns an exponentially distributed duration with the given mean.
func (r *rng) exp(mean time.Duration) time.Duration {
	return time.Duration(-math.Log(1-r.float()) * float64(mean))
}

func pick[T any](r *rng, xs []T) T { return xs[r.intn(len(xs))] }

type weighted[T any] struct {
	value  T
	weight int
}

func pickWeighted[T any](r *rng, ws []weighted[T]) T {
	total := 0
	for _, w := range ws {
		total += w.weight
	}
	n := r.intn(total)
	for _, w := range ws {
		if n < w.weight {
			return w.value
		}
		n -= w.weight
	}
	panic("unreachable")
}

// ipv6 returns a random address in the /48 2001:db8:<site>::.
func (r *rng) ipv6(site uint16) string {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	b[4], b[5] = byte(site>>8), byte(site)
	for i := 6; i < 16; i++ {
		b[i] = byte(r.next())
	}
	return netip.AddrFrom16(b).String()
}

// token returns n random lowercase letters and digits, for link paths.
func (r *rng) token(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.intn(len(chars))]
	}
	return string(b)
}

// dataset collects examples in any order and writes them sorted by time.
type dataset struct {
	items []item
}

type item struct {
	ex  replay.Example
	seq int
}

func (d *dataset) add(ev event.Event, label replay.Label) {
	ev.Time = ev.Time.UTC().Truncate(time.Millisecond)
	d.items = append(d.items, item{replay.Example{Event: ev, Label: label}, len(d.items)})
}

// write writes one example per line, in time order; events at the same
// instant keep the order they were added in.
func (d *dataset) write(w io.Writer) error {
	items := slices.Clone(d.items)
	slices.SortFunc(items, func(a, b item) int {
		if c := a.ex.Event.Time.Compare(b.ex.Event.Time); c != 0 {
			return c
		}
		return cmp.Compare(a.seq, b.seq)
	})
	bw := bufio.NewWriter(w)
	for _, it := range items {
		if err := it.ex.Event.Validate(); err != nil {
			return fmt.Errorf("%s event of %s at %s: %w", it.ex.Event.Type, it.ex.Event.AccountID, it.ex.Event.Time, err)
		}
		line, err := json.Marshal(it.ex)
		if err != nil {
			return err
		}
		bw.Write(line)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

// rates are the shares of recipients whose mail hard bounces, soft bounces
// or draws a spam complaint.
type rates struct{ hard, soft, complaint float64 }

// sender is an account sending mail with one API key.
type sender struct {
	account, key, from string
	label              replay.Label
	rates              rates
	subjects           []string
	// ip picks the IP of a send, to picks its recipients and links its
	// links.
	ip    func(r *rng) string
	to    func(r *rng) []string
	links func(r *rng) []string
	// blocked marks sends an enforced rule stops, so no feedback follows.
	blocked bool
}

func fixedIPs(ips ...string) func(r *rng) string {
	return func(r *rng) string { return pick(r, ips) }
}

func linksTo(host string) func(r *rng) []string {
	return func(r *rng) []string { return []string{"https://" + host + "/" + r.token(6)} }
}

func noLinks(*rng) []string { return nil }

// send adds a send at at and the feedback its recipients produce.
func (d *dataset) send(r *rng, s *sender, at time.Time) {
	ev := event.Event{
		Type:      event.Send,
		Time:      at,
		AccountID: s.account,
		APIKeyID:  s.key,
		IP:        s.ip(r),
		From:      s.from,
		To:        s.to(r),
		Subject:   pick(r, s.subjects),
		Links:     s.links(r),
	}
	d.add(ev, s.label)
	if !s.blocked {
		d.feedback(r, ev, s.rates)
	}
}

// feedback adds the bounces and complaints for a send. Feedback is not
// labeled: no reviewer judges a bounce, and scoring them would only pad the
// true negatives.
func (d *dataset) feedback(r *rng, send event.Event, rt rates) {
	for _, to := range send.To {
		u := r.float()
		var info event.FeedbackInfo
		var delay time.Duration
		switch {
		case u < rt.hard:
			info = event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent"}
			delay = 2*time.Second + r.exp(40*time.Second)
		case u < rt.hard+rt.soft:
			info = event.FeedbackInfo{Kind: event.Bounce, BounceType: "transient"}
			delay = 30*time.Second + r.exp(15*time.Minute)
		case u < rt.hard+rt.soft+rt.complaint:
			info = event.FeedbackInfo{Kind: event.Complaint}
			delay = time.Minute + r.exp(20*time.Minute)
		default:
			continue
		}
		info.Recipient = to
		d.add(event.Event{
			Type:      event.Feedback,
			Time:      send.Time.Add(delay),
			AccountID: send.AccountID,
			From:      send.From,
			Feedback:  &info,
		}, replay.Unlabeled)
	}
}

// accountEvent adds account activity. created is when the account was
// created, as the platform knows it.
func (d *dataset) accountEvent(at time.Time, account, ip, action, plan string, created time.Time, label replay.Label) {
	d.add(event.Event{
		Type:      event.Account,
		Time:      at,
		AccountID: account,
		IP:        ip,
		Account:   &event.AccountInfo{Action: action, CreatedAt: &created, Plan: plan},
	}, label)
}

// established adds the event that tells Catraca how old an account that
// existed before the dataset is: a login at the very start.
func (d *dataset) established(s *sender, ageDays int, plan string) {
	d.accountEvent(start, s.account, "", "login", plan, start.AddDate(0, 0, -ageDays), s.label)
}

// hourWeights is how mail spreads over a working day, by local hour.
var hourWeights = func() []weighted[int] {
	w := []int{1, 1, 1, 1, 1, 1, 2, 4, 8, 9, 9, 8, 6, 7, 8, 8, 7, 5, 4, 3, 3, 2, 2, 1}
	out := make([]weighted[int], len(w))
	for h, n := range w {
		out[h] = weighted[int]{h, n}
	}
	return out
}()

// steady adds about perDay sends a day, fewer on weekends, spread over the
// working hours of a sender tz hours from UTC, keeping those in [from, to).
func (d *dataset) steady(r *rng, s *sender, perDay, tz int, from, to time.Time) {
	for n := range days {
		midnight := day(n)
		count := perDay
		if wd := midnight.Weekday(); wd == time.Saturday || wd == time.Sunday {
			count = perDay * 2 / 5
		}
		count = count*4/5 + r.intn(count*2/5+1)
		for range count {
			hour := pickWeighted(r, hourWeights)
			at := midnight.Add(time.Duration(hour-tz)*time.Hour + r.within(time.Hour))
			if at.Before(from) || !at.Before(to) {
				continue
			}
			d.send(r, s, at)
		}
	}
}

// burst adds n sends spread evenly over [from, from+span), with jitter.
func (d *dataset) burst(r *rng, s *sender, n int, from time.Time, span time.Duration) {
	step := span / time.Duration(n)
	for i := range n {
		d.send(r, s, from.Add(time.Duration(i)*step+r.within(step)))
	}
}
