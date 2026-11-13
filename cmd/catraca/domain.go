package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/senderauth"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// newResolver returns the resolver domain check asks; tests replace it.
var newResolver = senderauth.NewSystemResolver

// listFlag is a flag that may be repeated, each value a comma-separated
// list.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for item := range strings.SplitSeq(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*l = append(*l, item)
		}
	}
	return nil
}

// domainReport is what domain check --json prints.
type domainReport struct {
	senderauth.Report
	// Signals are the domain signals rules would see once the result is
	// cached, but domain.verified, which comes from the event.
	Signals map[string]any `json:"signals"`
}

func (c *cli) domainCheck(ctx context.Context, args []string) int {
	fs := c.flagSet("domain check", `Usage: catraca domain check <domain> [--provider <domain>] [--selector <selector>] [--resolver <host:port>] [--json]

Looks up a sender domain's SPF record, the DKIM keys under the given
selectors and the DMARC policy that applies to it, live and outside any
cache, and prints each record, what was parsed from it and the states
rules read as domain.spf, domain.dkim and domain.dmarc_*.

It checks that the domain is set up to authenticate. It is not what a
receiver does: SPF is evaluated for no sending IP, and no DKIM signature
is verified.
`)
	var providers, selectors listFlag
	fs.Var(&providers, "provider", "a domain the SPF record should include, such as amazonses.com; repeat it or separate with commas")
	fs.Var(&selectors, "selector", "a DKIM selector to look up; repeat it or separate with commas")
	resolver := fs.String("resolver", "", "a DNS server to ask, host:port, instead of the system's resolver")
	timeout := fs.Duration("timeout", 10*time.Second, "how long to wait for every lookup together")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, code := parse(fs, args, 1, 1)
	if code >= 0 {
		return code
	}
	domain, err := senderauth.NormalizeDomain(pos[0])
	if err != nil {
		c.errorf("%v", err)
		return exitUsage
	}
	checker := &senderauth.Checker{Resolver: newResolver(*resolver), Selectors: selectors}
	for _, p := range providers {
		d, err := senderauth.NormalizeDomain(p)
		if err != nil {
			c.errorf("--provider: %v", err)
			return exitUsage
		}
		checker.Providers = append(checker.Providers, d)
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	rep := checker.Check(ctx, domain)
	out := domainReport{Report: rep, Signals: signal.SenderAuthSignals(rep.Result(time.Now()))}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return exitError
		}
		return exitOK
	}
	writeDomainReport(c.stdout, out, len(providers) > 0)
	return exitOK
}

func writeDomainReport(w io.Writer, r domainReport, providers bool) {
	line := func(label, format string, args ...any) {
		fmt.Fprintf(w, "  %-10s %s\n", label, fmt.Sprintf(format, args...))
	}
	fmt.Fprintf(w, "%s (organizational domain %s)\n\n", r.Domain, r.OrgDomain)

	spf := r.SPF
	fmt.Fprintf(w, "SPF        %s\n", spf.State)
	if spf.Record != "" {
		line("record", "%s", spf.Record)
	}
	if spf.State == senderauth.Found {
		line("all", "%s", spf.All)
	}
	switch {
	case spf.ProviderVia != "":
		line("provider", "%s: %s", spf.Provider, spf.ProviderVia)
	case providers:
		line("provider", "%s", spf.Provider)
	default:
		line("provider", "%s: no --provider given", spf.Provider)
	}
	if spf.State != senderauth.Missing {
		line("lookups", "%d of %d", spf.Lookups, senderauth.MaxSPFLookups)
	}
	for i, n := range spf.Tree {
		label := ""
		if i == 0 {
			label = "records"
		}
		name := n.Domain
		if n.Via != "" {
			name = n.Via + " " + name
		}
		if n.Error != "" && n.Depth > 0 {
			name += ": " + n.Error
		}
		line(label, "%s%s", strings.Repeat("  ", n.Depth), name)
	}
	for _, note := range spf.Notes {
		line("note", "%s", note)
	}
	if spf.Error != "" {
		line("error", "%s", spf.Error)
	}

	fmt.Fprintf(w, "\nDKIM       %s\n", r.DKIM.State)
	if len(r.DKIM.Selectors) == 0 {
		line("selectors", "none given: pass --selector")
	}
	for _, s := range r.DKIM.Selectors {
		detail := s.State
		switch {
		case s.Key != nil && s.State == senderauth.Found && s.Key.Type == "rsa":
			detail += fmt.Sprintf(": rsa, %d bits", s.Key.Bits)
		case s.Key != nil && s.State == senderauth.Found:
			detail += ": " + s.Key.Type
		case s.Error != "":
			detail += ": " + s.Error
		}
		if s.Key != nil && s.Key.Testing {
			detail += " (t=y: testing)"
		}
		line(s.Selector, "%s (%s)", detail, s.Name)
	}

	dm := r.DMARC
	fmt.Fprintf(w, "\nDMARC      %s\n", dm.State)
	if dm.Record != "" {
		line("record", "_dmarc.%s: %s", dm.RecordDomain, dm.Record)
	}
	if p := dm.Parsed; p != nil {
		switch dm.Applies {
		case "sp":
			line("applies", "sp, from the organizational domain's record")
		case "p":
			if dm.RecordDomain == r.Domain {
				line("applies", "p, the domain's own record")
			} else {
				line("applies", "p, from the organizational domain's record, which has no sp")
			}
		}
		sp := p.SP
		if sp == "" {
			sp = "(not set: p applies to subdomains)"
		}
		line("p", "%s", p.P)
		line("sp", "%s", sp)
		line("pct", "%d", p.Pct)
		line("adkim", "%s", p.ADKIM)
		line("aspf", "%s", p.ASPF)
		if p.RUA != "" {
			line("rua", "%s", p.RUA)
		}
		for _, warning := range p.Warnings {
			line("warning", "%s", warning)
		}
	}
	if dm.Error != "" {
		line("error", "%s", dm.Error)
	}

	fmt.Fprintf(w, "\nSignals, once cached\n")
	for _, s := range signal.Specs() {
		if v, ok := r.Signals[s.Name]; ok && s.Map == "domain" {
			if str, isString := v.(string); isString {
				v = fmt.Sprintf("%q", str)
			}
			fmt.Fprintf(w, "  domain.%-13s %v\n", s.Name, v)
		}
	}
	fmt.Fprint(w, "\nThis checks that the domain is set up to authenticate. It is not what a\n"+
		"receiver does: SPF is evaluated for no sending IP, and no DKIM signature\nis verified.\n")
}
