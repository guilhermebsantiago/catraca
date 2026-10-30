package app_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/audit"
)

const opsToken = "test-token-ops-0123456789abcdef0123"

// TestTokenScopes checks the scopes of catraca.yaml end to end: a send
// path token in the middle of a rotation decides with either value and
// reads nothing, and an ops token reads and labels, its name kept on the
// label.
func TestTokenScopes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, options{edit: func(yaml string) string {
		out := strings.Replace(yaml, "      token: "+token+"\n",
			"      token: "+newToken+"\n      previous_tokens: ["+token+"]\n      scopes: [decide]\n"+
				"    - name: ops\n      token: "+opsToken+"\n      scopes: [read, label]\n", 1)
		if !strings.Contains(out, "scopes: [decide]") {
			t.Fatalf("no scopes in the configuration:\n%s", out)
		}
		return out
	}})

	ev := map[string]any{"type": "send", "account_id": "acct_scope", "from": "a@scope.example", "to": []string{"b@box.example"}}
	var id string
	for _, tok := range []string{token, newToken} {
		r := h.do("POST", "/v1/decide", tok, ev)
		if r.status != http.StatusOK {
			t.Fatalf("decide with token %s...: %d %s", tok[:12], r.status, r.body)
		}
		var out struct {
			Decision struct{ ID string } `json:"decision"`
		}
		r.json(t, &out)
		id = out.Decision.ID
		for _, path := range []string{"/v1/rules", "/v1/decisions/" + id} {
			if r := h.do("GET", path, tok, nil); r.status != http.StatusForbidden || !strings.Contains(string(r.body), "insufficient_scope") {
				t.Errorf("GET %s with send path token %s...: %d %s, want 403 insufficient_scope", path, tok[:12], r.status, r.body)
			}
		}
	}
	if r := h.do("POST", "/v1/decide", opsToken, ev); r.status != http.StatusForbidden {
		t.Errorf("decide with the ops token: %d %s, want 403", r.status, r.body)
	}
	if r := h.do("POST", "/v1/rules/reload", opsToken, nil); r.status != http.StatusForbidden {
		t.Errorf("reload with the ops token: %d %s, want 403", r.status, r.body)
	}

	if r := h.do("POST", "/v1/decisions/"+id+"/labels", opsToken, `{"verdict":"false_positive","by":"appeals"}`); r.status != http.StatusCreated {
		t.Fatalf("label with the ops token: %d %s", r.status, r.body)
	}
	r := h.do("GET", "/v1/decisions/"+id, opsToken, nil)
	if r.status != http.StatusOK {
		t.Fatalf("read with the ops token: %d %s", r.status, r.body)
	}
	var entry audit.Entry
	r.json(t, &entry)
	if len(entry.Labels) != 1 || entry.Labels[0].Client != "ops" || entry.Labels[0].By != "appeals" {
		t.Errorf("labels = %+v, want one by appeals from the ops token", entry.Labels)
	}
}
