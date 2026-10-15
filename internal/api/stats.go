package api

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/precision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// ParseSince parses the start of a stats window: a duration back from now
// ("720h", "90m"), a number of days ("30d") or an RFC 3339 time
// ("2026-10-01T00:00:00Z") or date ("2026-10-01").
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return time.Time{}, errSince
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return time.Time{}, errSince
		}
	}
	if d <= 0 {
		return time.Time{}, errors.New("the window must be positive")
	}
	return now.Add(-d), nil
}

var errSince = errors.New("want a duration such as 720h, a number of days such as 30d, or an RFC 3339 time")

// RuleInfos describes the rules of rs for the precision gate.
func RuleInfos(rs *rules.Ruleset) []precision.RuleInfo {
	out := make([]precision.RuleInfo, 0, len(rs.Rules()))
	for _, r := range rs.Rules() {
		out = append(out, precision.RuleInfo{ID: r.ID, Mode: r.Mode, HasOverride: r.Override != nil})
	}
	return out
}
