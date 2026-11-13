package senderauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// DMARC policies, the values of DMARCRecord.P and SP and, besides missing,
// invalid and unknown, of the dmarc_policy signal.
const (
	PolicyNone       = "none"
	PolicyQuarantine = "quarantine"
	PolicyReject     = "reject"
)

// Alignment modes of adkim and aspf, as the signals spell them.
const (
	Relaxed = "relaxed"
	Strict  = "strict"
)

// DMARCRecord is a parsed DMARC record (RFC 7489 section 6.3).
type DMARCRecord struct {
	// P is the policy for the domain: none, quarantine or reject.
	P string `json:"p"`
	// SP is the policy for its subdomains, "" when the record leaves it
	// out and P applies to them too.
	SP string `json:"sp,omitempty"`
	// Pct is the share of failing mail the policy applies to, 0 to 100;
	// default 100.
	Pct int `json:"pct"`
	// ADKIM and ASPF are the DKIM and SPF alignment modes, relaxed (the
	// default) or strict.
	ADKIM string `json:"adkim"`
	ASPF  string `json:"aspf"`
	// RUA is where aggregate reports go, as written.
	RUA string `json:"rua,omitempty"`
	// Warnings are the problems the parser worked around as RFC 7489
	// says to: an invalid optional tag takes its default.
	Warnings []string `json:"warnings,omitempty"`
}

// isDMARC reports whether a TXT record at _dmarc is a DMARC record: its
// first tag is v=DMARC1. Others are discarded, as RFC 7489 says.
func isDMARC(txt string) bool {
	first, _, _ := strings.Cut(txt, ";")
	k, v, ok := strings.Cut(first, "=")
	return ok && strings.EqualFold(strings.TrimSpace(k), "v") && strings.EqualFold(strings.TrimSpace(v), "DMARC1")
}

// ParseDMARC parses a DMARC record. It fails for a record that does not
// start with v=DMARC1, or whose p tag is missing or invalid, or whose sp
// tag is invalid, unless the record has a valid rua: then, as RFC 7489
// section 6.6.3 says, it reads as p=none. Other invalid tags take their
// default with a warning; unknown tags are ignored.
//
// Tag values are matched without regard to case, as receivers do.
func ParseDMARC(record string) (DMARCRecord, error) {
	if !isDMARC(record) {
		return DMARCRecord{}, errors.New("does not start with v=DMARC1")
	}
	rec := DMARCRecord{Pct: 100, ADKIM: Relaxed, ASPF: Relaxed}
	var p, sp string
	var hasP, hasSP bool
	seen := map[string]bool{}
	tags := strings.Split(record, ";")
	for _, tag := range tags[1:] {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		k, v, ok := strings.Cut(tag, "=")
		if !ok {
			rec.Warnings = append(rec.Warnings, fmt.Sprintf("%q is not a tag=value pair: ignored", tag))
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if seen[k] {
			rec.Warnings = append(rec.Warnings, fmt.Sprintf("%s appears more than once: the first one counts", k))
			continue
		}
		seen[k] = true
		switch k {
		case "v":
			rec.Warnings = append(rec.Warnings, "v appears again after the first tag: ignored")
		case "p":
			p, hasP = strings.ToLower(v), true
		case "sp":
			sp, hasSP = strings.ToLower(v), true
		case "pct":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 100 || strings.HasPrefix(v, "+") {
				rec.Warnings = append(rec.Warnings, fmt.Sprintf("pct=%s is not a whole number from 0 to 100: 100 applies", v))
				continue
			}
			rec.Pct = n
		case "adkim", "aspf":
			mode, ok := alignmentModes[strings.ToLower(v)]
			if !ok {
				rec.Warnings = append(rec.Warnings, fmt.Sprintf("%s=%s is not r or s: relaxed applies", k, v))
				continue
			}
			if k == "adkim" {
				rec.ADKIM = mode
			} else {
				rec.ASPF = mode
			}
		case "rua":
			rec.RUA = v
		}
	}

	var problem string
	switch {
	case !hasP:
		problem = "the p tag is missing"
	case !validPolicy(p):
		problem = fmt.Sprintf("p=%s is not none, quarantine or reject", p)
	case hasSP && !validPolicy(sp):
		problem = fmt.Sprintf("sp=%s is not none, quarantine or reject", sp)
	}
	if problem == "" {
		rec.P = p
		if hasSP {
			rec.SP = sp
		}
		return rec, nil
	}
	if !validRUA(rec.RUA) {
		return DMARCRecord{}, errors.New(problem)
	}
	rec.P, rec.SP = PolicyNone, ""
	rec.Warnings = append(rec.Warnings, problem+": the record has a valid rua, so receivers read it as p=none (RFC 7489 section 6.6.3)")
	return rec, nil
}

var alignmentModes = map[string]string{"r": Relaxed, "s": Strict}

func validPolicy(p string) bool {
	return p == PolicyNone || p == PolicyQuarantine || p == PolicyReject
}

// validRUA reports whether rua holds at least one URI with a scheme, such
// as mailto:dmarc@example.com.
func validRUA(rua string) bool {
	for u := range strings.SplitSeq(rua, ",") {
		if parsed, err := url.Parse(strings.TrimSpace(u)); err == nil && parsed.Scheme != "" && parsed.Opaque+parsed.Host+parsed.Path != "" {
			return true
		}
	}
	return false
}

// DMARCReport is what checking a domain's DMARC policy found.
type DMARCReport struct {
	// State is the policy that applies to the domain, none, quarantine or
	// reject, or missing, invalid or unknown.
	State string `json:"state"`
	// RecordDomain is where the record was found: the domain, or its
	// organizational domain when the domain has none.
	RecordDomain string `json:"record_domain,omitempty"`
	Record       string `json:"record,omitempty"`
	// Applies is "p" or "sp": which of the record's policies applies. sp
	// applies, when set, to a subdomain that has no record of its own.
	Applies string `json:"applies,omitempty"`
	// Parsed is the record, when it parsed.
	Parsed *DMARCRecord `json:"parsed,omitempty"`
	// Error says why State is invalid or unknown.
	Error string `json:"error,omitempty"`
}

// checkDMARC finds the DMARC policy that applies to domain: the record at
// _dmarc.<domain>, or when there is none, the one at _dmarc.<org>, whose sp
// applies to subdomains (RFC 7489 section 6.6.3).
func checkDMARC(ctx context.Context, lookup func(context.Context, string) ([]string, error), domain, org string) DMARCReport {
	recs, rep := dmarcRecords(ctx, lookup, domain)
	at := domain
	if rep.State == Missing && org != domain {
		recs, rep = dmarcRecords(ctx, lookup, org)
		at = org
	}
	if rep.State != "" {
		return rep
	}
	rep.RecordDomain, rep.Record = at, recs[0]
	parsed, err := ParseDMARC(recs[0])
	if err != nil {
		rep.State, rep.Error = Invalid, err.Error()
		return rep
	}
	rep.Parsed = &parsed
	rep.State, rep.Applies = parsed.P, "p"
	if at != domain && parsed.SP != "" {
		rep.State, rep.Applies = parsed.SP, "sp"
	}
	return rep
}

// dmarcRecords looks up the DMARC records of domain. It returns them with
// an empty report when there is exactly one, and otherwise the report of a
// missing, invalid (several records, which receivers ignore) or unknown
// policy.
func dmarcRecords(ctx context.Context, lookup func(context.Context, string) ([]string, error), domain string) ([]string, DMARCReport) {
	name := "_dmarc." + domain
	txts, err := lookup(ctx, name)
	if err != nil && !isNotFound(err) {
		return nil, DMARCReport{State: Unknown, Error: fmt.Sprintf("looking up %s: %v", name, err)}
	}
	var recs []string
	for _, t := range txts {
		if isDMARC(t) {
			recs = append(recs, t)
		}
	}
	switch len(recs) {
	case 0:
		return nil, DMARCReport{State: Missing}
	case 1:
		return recs, DMARCReport{}
	}
	return nil, DMARCReport{State: Invalid, RecordDomain: domain,
		Error: fmt.Sprintf("%s has %d DMARC records; receivers apply none of them", name, len(recs))}
}
