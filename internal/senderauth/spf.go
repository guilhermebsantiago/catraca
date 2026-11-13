package senderauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// MaxSPFLookups is RFC 7208's limit (section 4.6.4) on the terms that cause
// DNS queries in one SPF evaluation: include, a, mx, ptr, exists and
// redirect. A record that needs more is a permanent error.
const MaxSPFLookups = 10

// SPFTerm is one term of an SPF record: a mechanism, with its qualifier, or
// a modifier.
type SPFTerm struct {
	// Qualifier is "+", "-", "~" or "?" for a mechanism, "+" when the record
	// leaves it out, and "" for a modifier.
	Qualifier string `json:"qualifier,omitempty"`
	// Name is the mechanism or modifier name, lowercase: all, include, a,
	// mx, ptr, ip4, ip6, exists, redirect, exp, or an unknown modifier.
	Name string `json:"name"`
	// Value is what follows the name and its ':' or '=', as written: a
	// domain-spec, a network, a CIDR length.
	Value    string `json:"value,omitempty"`
	Modifier bool   `json:"modifier,omitempty"`
}

func (t SPFTerm) String() string {
	switch {
	case t.Modifier:
		return t.Name + "=" + t.Value
	case t.Value == "":
		return t.Name
	case (t.Name == "a" || t.Name == "mx") && cidrOnly.MatchString(t.Value):
		return t.Name + t.Value
	}
	return t.Name + ":" + t.Value
}

// SPFRecord is a parsed SPF record.
type SPFRecord struct {
	Terms []SPFTerm `json:"terms"`
}

// redirect returns the domain-spec of the record's redirect modifier, or "".
func (r SPFRecord) redirect() string {
	for _, t := range r.Terms {
		if t.Modifier && t.Name == "redirect" {
			return t.Value
		}
	}
	return ""
}

// isSPF reports whether a TXT record is an SPF record: one that starts
// with exactly "v=spf1", ended by a space or the end of the record (RFC
// 7208 section 4.5).
func isSPF(txt string) bool {
	return len(txt) >= 6 && strings.EqualFold(txt[:6], "v=spf1") && (len(txt) == 6 || txt[6] == ' ')
}

var (
	// modifierName is the name of a modifier, before its '='.
	modifierName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
	// cidrSuffix splits the dual CIDR length off an a or mx mechanism.
	cidrSuffix = regexp.MustCompile(`^(.*?)((?:/[0-9]+)?(?://[0-9]+)?)$`)
	// cidrOnly matches the value of an a or mx mechanism without a domain.
	cidrOnly = regexp.MustCompile(`^(?:/[0-9]+)?(?://[0-9]+)?$`)
)

// ParseSPF parses an SPF record (RFC 7208 section 12). It fails, which a
// receiver reads as a permanent error, for a record that does not start
// with v=spf1, has an unknown mechanism, a malformed domain-spec, network or
// macro, or more than one redirect or exp modifier.
//
// Macros are checked for syntax only. They are expanded with the sending IP
// and address, which a pre-send check does not have.
func ParseSPF(record string) (SPFRecord, error) {
	if !isSPF(record) {
		return SPFRecord{}, errors.New("does not start with v=spf1")
	}
	var rec SPFRecord
	seen := map[string]bool{}
	for _, field := range strings.Fields(record[6:]) {
		t, err := parseSPFTerm(field)
		if err != nil {
			return SPFRecord{}, err
		}
		if t.Modifier && (t.Name == "redirect" || t.Name == "exp") {
			if seen[t.Name] {
				return SPFRecord{}, fmt.Errorf("%s appears more than once", t.Name)
			}
			seen[t.Name] = true
		}
		rec.Terms = append(rec.Terms, t)
	}
	return rec, nil
}

func parseSPFTerm(field string) (SPFTerm, error) {
	if name, value, ok := strings.Cut(field, "="); ok && modifierName.MatchString(name) {
		t := SPFTerm{Name: strings.ToLower(name), Value: value, Modifier: true}
		var err error
		switch t.Name {
		case "redirect", "exp":
			_, err = checkDomainSpec(value)
		default:
			// Unknown modifiers are ignored, but their value is a
			// macro-string.
			_, err = checkMacroString(value)
		}
		if err != nil {
			return SPFTerm{}, fmt.Errorf("%s: %v", field, err)
		}
		return t, nil
	}

	t := SPFTerm{Qualifier: "+"}
	rest := field
	if strings.ContainsAny(rest[:1], "+-~?") {
		t.Qualifier, rest = rest[:1], rest[1:]
	}
	end := strings.IndexAny(rest, ":/")
	if end < 0 {
		end = len(rest)
	}
	t.Name = strings.ToLower(rest[:end])
	arg := rest[end:]
	fail := func(format string, args ...any) (SPFTerm, error) {
		return SPFTerm{}, fmt.Errorf("%s: "+format, append([]any{field}, args...)...)
	}
	switch t.Name {
	case "all":
		if arg != "" {
			return fail("all takes no argument")
		}
	case "include", "exists":
		spec, ok := strings.CutPrefix(arg, ":")
		if !ok || spec == "" {
			return fail("%s needs a domain", t.Name)
		}
		if _, err := checkDomainSpec(spec); err != nil {
			return fail("%v", err)
		}
		t.Value = spec
	case "ptr":
		if arg != "" {
			spec, ok := strings.CutPrefix(arg, ":")
			if !ok || spec == "" {
				return fail("ptr takes :domain")
			}
			if _, err := checkDomainSpec(spec); err != nil {
				return fail("%v", err)
			}
			t.Value = spec
		}
	case "a", "mx":
		m := cidrSuffix.FindStringSubmatch(arg)
		spec, cidr := m[1], m[2]
		if err := checkDualCIDR(cidr); err != nil {
			return fail("%v", err)
		}
		if spec != "" {
			spec, ok := strings.CutPrefix(spec, ":")
			if !ok || spec == "" {
				return fail("%s takes :domain and a CIDR length", t.Name)
			}
			if _, err := checkDomainSpec(spec); err != nil {
				return fail("%v", err)
			}
		}
		t.Value = strings.TrimPrefix(arg, ":")
	case "ip4", "ip6":
		network, ok := strings.CutPrefix(arg, ":")
		if !ok || network == "" {
			return fail("%s needs a network", t.Name)
		}
		addr, length, hasLength := strings.Cut(network, "/")
		ip, err := netip.ParseAddr(addr)
		max := 32
		if t.Name == "ip6" {
			max = 128
		}
		switch {
		case err != nil || ip.Zone() != "":
			return fail("invalid address %q", addr)
		case t.Name == "ip4" && !ip.Is4():
			return fail("%q is not an IPv4 address", addr)
		case t.Name == "ip6" && !ip.Is6():
			return fail("%q is not an IPv6 address", addr)
		case hasLength && !validCIDR(length, max):
			return fail("invalid CIDR length /%s", length)
		}
		t.Value = network
	default:
		return fail("unknown mechanism %q", t.Name)
	}
	return t, nil
}

// checkDualCIDR checks the dual-cidr-length of an a or mx mechanism:
// "", "/24", "//64" or "/24//64".
func checkDualCIDR(s string) error {
	if s == "" {
		return nil
	}
	v4, v6, dual := strings.Cut(s, "//")
	if v4 != "" && !validCIDR(strings.TrimPrefix(v4, "/"), 32) {
		return fmt.Errorf("invalid IPv4 CIDR length %s", v4)
	}
	if dual && !validCIDR(v6, 128) {
		return fmt.Errorf("invalid IPv6 CIDR length //%s", v6)
	}
	return nil
}

// validCIDR reports whether s is a CIDR length from 0 to max without
// leading zeros.
func validCIDR(s string, max int) bool {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= max
}

// checkMacroString checks the syntax of an SPF macro-string (RFC 7208
// section 7.1) and reports whether it has macros to expand.
func checkMacroString(s string) (macros bool, err error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return false, fmt.Errorf("invalid character %q", c)
		}
		if c != '%' {
			continue
		}
		if i+1 == len(s) {
			return false, errors.New("'%' at the end")
		}
		switch s[i+1] {
		case '%', '_', '-':
			i++
			continue
		case '{':
		default:
			return false, fmt.Errorf("'%%' followed by %q; want %%{...}, %%%%, %%_ or %%-", s[i+1])
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return false, errors.New("unterminated macro")
		}
		if !validMacro(s[i+2 : i+end]) {
			return false, fmt.Errorf("invalid macro %q", s[i:i+end+1])
		}
		macros = true
		i += end
	}
	return macros, nil
}

// validMacro checks the inside of %{...}: a macro letter, an optional
// count of labels, an optional r and optional delimiters.
func validMacro(m string) bool {
	if m == "" || !strings.ContainsRune("slodiphcrtvSLODIPHCRTV", rune(m[0])) {
		return false
	}
	i := 1
	for i < len(m) && m[i] >= '0' && m[i] <= '9' {
		i++
	}
	if i < len(m) && (m[i] == 'r' || m[i] == 'R') {
		i++
	}
	for ; i < len(m); i++ {
		if !strings.ContainsRune(".-+,/_=", rune(m[i])) {
			return false
		}
	}
	return true
}

// checkDomainSpec checks an SPF domain-spec: a macro-string that ends with
// a macro or with "." and a top label (RFC 7208 section 7.1), so
// "include:com" is malformed. It reports whether the spec has macros.
func checkDomainSpec(spec string) (macros bool, err error) {
	if macros, err = checkMacroString(spec); err != nil {
		return false, err
	}
	if strings.HasSuffix(spec, "}") && macros {
		return true, nil
	}
	d := strings.TrimSuffix(spec, ".")
	dot := strings.LastIndexByte(d, '.')
	if dot < 0 || !isTopLabel(d[dot+1:]) {
		return false, fmt.Errorf("%q does not end with a top-level domain", spec)
	}
	return macros, nil
}

// isTopLabel reports whether s is an RFC 7208 toplabel: letters, digits and
// inner hyphens, with a letter or a hyphen, so not all digits.
func isTopLabel(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	digitsOnly := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
			digitsOnly = false
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return !digitsOnly
}

// literalDomain returns a domain-spec as a domain to look up, or false when
// it has macros, which only a receiver can expand. %%, %_ and %- expand to
// characters no hostname has, so they count as macros too.
func literalDomain(spec string) (string, bool) {
	if strings.Contains(spec, "%") {
		return "", false
	}
	return strings.ToLower(strings.TrimSuffix(spec, ".")), true
}

// SPF qualifier results, the values of SPFReport.All and of the spf_all
// signal besides unknown.
const (
	AllPass     = "pass"
	AllFail     = "fail"
	AllSoftfail = "softfail"
	AllNeutral  = "neutral"
	AllNone     = "none"
)

func qualifierResult(q string) string {
	switch q {
	case "+":
		return AllPass
	case "-":
		return AllFail
	case "~":
		return AllSoftfail
	case "?":
		return AllNeutral
	}
	return AllNone
}

// Values of the provider answers.
const (
	Yes = "yes"
	No  = "no"
)

// SPFReport is what checking a domain's SPF record found.
type SPFReport struct {
	// State is found, missing, invalid or unknown.
	State string `json:"state"`
	// Record is the domain's SPF record, when it has one.
	Record string `json:"record,omitempty"`
	// All is what the record ends with: pass (+all), fail (-all),
	// softfail (~all), neutral (?all), none when it has no all mechanism,
	// following redirect, or unknown unless State is found.
	All string `json:"all"`
	// Provider is yes when the record reaches one of the configured
	// providers through include or redirect, with every qualifier on the
	// way a pass; no when it does not, or the record is missing or
	// invalid; unknown when no provider is configured, a lookup failed
	// before one was reached, or an include with macros might expand to
	// one.
	Provider string `json:"provider"`
	// ProviderVia names the term that reached the provider.
	ProviderVia string `json:"provider_via,omitempty"`
	// Lookups counts the terms that cause DNS queries, as a receiver
	// would, up to the first one past MaxSPFLookups.
	Lookups int `json:"lookups"`
	// Error says why State is invalid or unknown.
	Error string `json:"error,omitempty"`
	// Tree lists the records visited, in evaluation order: the domain's,
	// then each include and redirect target, with its depth.
	Tree []SPFNode `json:"tree,omitempty"`
	// Notes are what was not evaluated, such as macros.
	Notes []string `json:"notes,omitempty"`
}

// SPFNode is one record visited while checking SPF.
type SPFNode struct {
	Domain string `json:"domain"`
	// Via is "include", "redirect", or "" for the domain itself.
	Via    string `json:"via,omitempty"`
	Depth  int    `json:"depth"`
	Record string `json:"record,omitempty"`
	Error  string `json:"error,omitempty"`
}

// spfError stops an SPF walk: a permanent error, or a temporary one when
// temp is set.
type spfError struct {
	temp bool
	msg  string
}

func (e *spfError) Error() string { return e.msg }

func permErr(format string, args ...any) error {
	return &spfError{msg: fmt.Sprintf(format, args...)}
}

// errSPFMissing ends the walk of a domain without an SPF record.
var errSPFMissing = errors.New("no SPF record")

// spfWalk visits an SPF record and the records it includes in the order a
// receiver evaluates them, for an IP that matches no mechanism: the
// evaluation that makes the most DNS queries. It resolves the include and
// redirect targets, and counts the a, mx, ptr and exists terms without
// resolving them.
type spfWalk struct {
	lookup    func(name string) ([]string, error)
	providers []string
	rep       *SPFReport
	// macroOnPath is set when an include or redirect with macros, which
	// could expand to a provider, sits on a pass path.
	macroOnPath bool
}

// checkSPF checks the SPF record of domain.
func checkSPF(ctx context.Context, lookup func(context.Context, string) ([]string, error), domain string, providers []string) SPFReport {
	rep := SPFReport{}
	w := &spfWalk{
		lookup:    func(name string) ([]string, error) { return lookup(ctx, name) },
		providers: providers,
		rep:       &rep,
	}
	all, err := w.record(domain, "", 0, nil, true)
	var serr *spfError
	switch {
	case errors.Is(err, errSPFMissing):
		rep.State = Missing
	case errors.As(err, &serr) && serr.temp:
		rep.State, rep.Error = Unknown, serr.msg
	case err != nil:
		rep.State, rep.Error = Invalid, err.Error()
	default:
		rep.State = Found
	}
	rep.All = Unknown
	if rep.State == Found {
		rep.All = qualifierResult(all)
	}
	switch {
	case len(providers) == 0:
		rep.Provider = Unknown
	case rep.ProviderVia != "":
		// Reached before anything stopped the walk, so a receiver
		// evaluating mail from the provider reaches it too.
		rep.Provider = Yes
	case rep.State == Unknown, w.macroOnPath:
		rep.Provider = Unknown
	default:
		rep.Provider = No
	}
	return rep
}

// record visits the SPF record of name and returns the qualifier of the all
// mechanism that ends its evaluation, or "" when there is none. via is how
// it was reached ("" for the domain itself), path the records that led to
// it, and pass whether every include on the way had a pass qualifier.
func (w *spfWalk) record(name, via string, depth int, path []string, pass bool) (string, error) {
	node := len(w.rep.Tree)
	w.rep.Tree = append(w.rep.Tree, SPFNode{Domain: name, Via: via, Depth: depth})
	fail := func(err error) (string, error) {
		w.rep.Tree[node].Error = err.Error()
		return "", err
	}
	txts, err := w.lookup(name)
	if err != nil && !isNotFound(err) {
		return fail(&spfError{temp: true, msg: fmt.Sprintf("looking up %s: %v", name, err)})
	}
	var recs []string
	for _, t := range txts {
		if isSPF(t) {
			recs = append(recs, t)
		}
	}
	switch {
	case len(recs) == 0 && depth == 0:
		return fail(errSPFMissing)
	case len(recs) == 0:
		return fail(permErr("%s target %s has no SPF record", via, name))
	case len(recs) > 1:
		return fail(permErr("%s publishes %d SPF records; it must publish one", name, len(recs)))
	}
	w.rep.Tree[node].Record = recs[0]
	if depth == 0 {
		w.rep.Record = recs[0]
	}
	rec, err := ParseSPF(recs[0])
	if err != nil {
		return fail(permErr("%s: %v", name, err))
	}
	path = append(path, name)

	for _, t := range rec.Terms {
		if t.Modifier {
			continue
		}
		switch t.Name {
		case "all":
			// Terms after all are never evaluated, and a redirect is
			// ignored when the record has all.
			return t.Qualifier, nil
		case "include":
			if _, err := w.visit(t, "include", name, depth, path, pass && t.Qualifier == "+"); err != nil {
				return "", err
			}
		case "a", "mx", "ptr", "exists":
			if err := w.count(); err != nil {
				return fail(err)
			}
			if t.Name == "ptr" {
				w.rep.Notes = append(w.rep.Notes, fmt.Sprintf("%s uses ptr, which RFC 7208 asks domains not to publish: it is slow and many receivers skip it", name))
			}
		}
	}
	if spec := rec.redirect(); spec != "" {
		// The target's evaluation replaces this record's, all included.
		return w.visit(SPFTerm{Name: "redirect", Value: spec, Modifier: true}, "redirect", name, depth, path, pass)
	}
	return "", nil
}

// visit counts an include or redirect and visits its target. pass is
// whether every include on the way, this one included, has a pass
// qualifier.
func (w *spfWalk) visit(t SPFTerm, via, from string, depth int, path []string, pass bool) (string, error) {
	if err := w.count(); err != nil {
		w.rep.Tree = append(w.rep.Tree, SPFNode{Domain: t.Value, Via: via, Depth: depth + 1, Error: err.Error()})
		return "", err
	}
	target, ok := literalDomain(t.Value)
	if !ok {
		w.rep.Notes = append(w.rep.Notes, fmt.Sprintf("%s in %s has macros, which are expanded with the sending IP and address: not evaluated", t, from))
		if pass {
			w.macroOnPath = true
		}
		return "", nil
	}
	if pass && w.rep.ProviderVia == "" && slices.Contains(w.providers, target) {
		w.rep.ProviderVia = t.String() + " in " + from
	}
	if slices.Contains(path, target) {
		err := permErr("%s loop: %s", via, strings.Join(append(slices.Clone(path), target), " -> "))
		w.rep.Tree = append(w.rep.Tree, SPFNode{Domain: target, Via: via, Depth: depth + 1, Error: err.Error()})
		return "", err
	}
	return w.record(target, via, depth+1, path, pass)
}

// count counts a term that causes a DNS query.
func (w *spfWalk) count() error {
	w.rep.Lookups++
	if w.rep.Lookups > MaxSPFLookups {
		return permErr("more than %d DNS lookups (RFC 7208 section 4.6.4)", MaxSPFLookups)
	}
	return nil
}
