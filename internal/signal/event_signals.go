package signal

import (
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/guilhermebsantiago/catraca/internal/event"
)

// facts are values derived from an event that both the event map and the
// counters use.
type facts struct {
	fromDomain  string
	toDomains   []string // distinct, sorted
	linkDomains []string // distinct, sorted
	// ip is the event's IP in canonical form, so the same address spelled
	// two ways shares counters. It is the IP as sent when it does not parse.
	ip string
}

func factsOf(ev event.Event) facts {
	f := facts{
		fromDomain:  event.DomainOf(ev.From),
		toDomains:   distinctSorted(ev.To, event.DomainOf),
		linkDomains: distinctSorted(ev.Links, hostOf),
		ip:          ev.IP,
	}
	if a, err := netip.ParseAddr(ev.IP); err == nil {
		f.ip = a.Unmap().WithZone("").String()
	}
	return f
}

// eventSignals returns the event map. Every name is always present, with a
// zero value when the event does not carry it.
func eventSignals(ev event.Event, f facts) map[string]any {
	m := map[string]any{
		"type":           string(ev.Type),
		"account_id":     ev.AccountID,
		"api_key_id":     ev.APIKeyID,
		"ip":             ev.IP,
		"from_domain":    f.fromDomain,
		"recipients":     int64(len(ev.To)),
		"to_domains":     f.toDomains,
		"link_domains":   f.linkDomains,
		"links":          int64(len(ev.Links)),
		"subject_length": int64(utf8.RuneCountInString(ev.Subject)),
		"feedback_kind":  "",
		"bounce_type":    "",
		"account_action": "",
		"attributes":     map[string]string{},
	}
	if ev.Feedback != nil {
		m["feedback_kind"] = string(ev.Feedback.Kind)
		m["bounce_type"] = ev.Feedback.BounceType
	}
	if ev.Account != nil {
		m["account_action"] = ev.Account.Action
	}
	if ev.Attributes != nil {
		m["attributes"] = maps.Clone(ev.Attributes)
	}
	return m
}

// distinctSorted maps each value with fn and returns the distinct non-empty
// results, sorted. It never returns nil, so rules see an empty list.
func distinctSorted(values []string, fn func(string) string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if d := fn(v); d != "" {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// hostOf returns the lowercase hostname of a link, or "" when it has none.
// Links without a scheme, such as "example.com/offer", are read as http.
func hostOf(link string) string {
	link = strings.TrimSpace(link)
	if !strings.Contains(link, "://") {
		link = "http://" + link
	}
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}
