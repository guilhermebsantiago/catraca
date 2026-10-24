package app_test

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/api"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/signature"
)

// The secrets a rotation moves to; the harness's own become the previous
// ones.
const (
	newToken  = "test-token-next-0123456789abcdef0123"
	newSecret = "test-secret-next-0123456789abcdef0123"
)

// rotated moves every token and secret of the harness's configuration to a
// new value and keeps the old one as previous, as the middle step of a
// rotation does.
func rotated(yaml string) string {
	yaml = strings.Replace(yaml, "      token: "+token+"\n",
		"      token: "+newToken+"\n      previous_tokens: ["+token+"]\n", 1)
	return regexp.MustCompile(`(?m)^(\s*)secret: `+secret+`$`).
		ReplaceAllString(yaml, "${1}secret: "+newSecret+"\n${1}previous_secrets: ["+secret+"]")
}

// TestRotationOverlap checks that in the middle of a rotation every peer is
// served whichever secret it has: a client with either token, a platform
// signing feedback with either secret, and a resolver and a webhook
// receiver that still verify with the old one.
func TestRotationOverlap(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{edit: func(yaml string) string {
		out := rotated(yaml)
		// The hook, both feedback providers and the resolver.
		if n := strings.Count(out, "previous_secrets:"); n != 4 || !strings.Contains(out, "previous_tokens:") {
			t.Fatalf("rotated %d secrets, want 4 and the token:\n%s", n, out)
		}
		return out
	}})

	// Both tokens authenticate the same client.
	for _, tok := range []string{token, newToken} {
		r := h.do("GET", "/v1/rules", tok, nil)
		if r.status != http.StatusOK {
			t.Fatalf("token %s...: %d %s", tok[:12], r.status, r.body)
		}
		id := r.header.Get(api.RequestIDHeader)
		for _, l := range strings.Split(h.logs.String(), "\n") {
			if strings.Contains(l, `"request_id":"`+id+`"`) && !strings.Contains(l, `"client":"test"`) {
				t.Errorf("token %s... is not logged as client test: %s", tok[:12], l)
			}
		}
	}
	if r := h.do("GET", "/v1/rules", "test-token-never-0123456789abcdef", nil); r.status != http.StatusUnauthorized {
		t.Errorf("an unknown token: %d", r.status)
	}

	// Feedback signed with either secret counts.
	for i, key := range []string{secret, newSecret} {
		body := fmt.Sprintf(`{"id":"fb_rot_%d","account_id":"acct_fb","feedback":{"kind":"complaint"}}`, i)
		if r := h.signedFeedback(body, key); r.status != http.StatusAccepted {
			t.Errorf("feedback signed with secret %d: %d %s", i, r.status, r.body)
		}
	}

	// The resolver verifies with the old secret only, and still answers:
	// the leaked key is blocked.
	if r := h.postLeaks(leakBatch); r.status != http.StatusAccepted {
		t.Fatalf("batch: %d %s", r.status, r.body)
	}
	attempts := 0
	eventually(t, 10*time.Second, func() bool {
		attempts++
		d, _ := h.decide(send(fmt.Sprintf("acct_rot_%d", attempts), "app@leak.example", "api_key_id", "key_leaked"))
		return d.Action == decision.Block
	})

	// The revoke_key webhook carries a signature for each secret, so the
	// receiver accepts it before and after it switches.
	var got hookCall
	eventually(t, 10*time.Second, func() bool {
		calls := h.hook.calls()
		if len(calls) > 0 {
			got = calls[0]
		}
		return len(calls) > 0
	})
	for _, key := range []string{secret, newSecret} {
		if err := signature.Verify(key, got.signature, got.body, 0); err != nil {
			t.Errorf("a receiver with one of the secrets refuses the webhook: %v", err)
		}
	}
	if strings.Count(got.signature, "v1=") != 2 {
		t.Errorf("signature %q, want two v1 values", got.signature)
	}
}
