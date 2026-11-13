package senderauth

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSystemResolver asks real DNS, and runs only with CATRACA_TEST_DNS=1:
// it checks that the system resolver tells a missing record from an
// answer on this platform. CATRACA_TEST_DNS_SERVER, host:port, asks that
// server instead.
func TestSystemResolver(t *testing.T) {
	if os.Getenv("CATRACA_TEST_DNS") != "1" {
		t.Skip("set CATRACA_TEST_DNS=1 to ask real DNS")
	}
	c := &Checker{Resolver: NewSystemResolver(os.Getenv("CATRACA_TEST_DNS_SERVER")), Providers: []string{"_spf.google.com"}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rep := c.Check(ctx, "gmail.com")
	if rep.SPF.State != Found || rep.SPF.Provider != Yes {
		t.Errorf("gmail.com SPF = %+v, want found and including _spf.google.com", rep.SPF)
	}
	if !validPolicy(rep.DMARC.State) {
		t.Errorf("gmail.com DMARC = %+v, want a policy", rep.DMARC)
	}
	// .invalid never resolves (RFC 6761): NXDOMAIN, so missing, not unknown.
	rep = c.Check(ctx, "catraca-test.invalid")
	if rep.SPF.State != Missing || rep.DMARC.State != Missing {
		t.Errorf("catraca-test.invalid: SPF %s (%s), DMARC %s (%s); want both missing",
			rep.SPF.State, rep.SPF.Error, rep.DMARC.State, rep.DMARC.Error)
	}
}
