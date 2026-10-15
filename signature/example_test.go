package signature_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/signature"
)

// A platform endpoint that receives Catraca's effect webhooks checks the
// signature on the raw body before it acts.
func ExampleVerify() {
	const secret = "whsec_0123456789abcdef"

	revokeKey := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		err = signature.Verify(secret, r.Header.Get(signature.Header), body, 0)
		switch {
		case errors.Is(err, signature.ErrMalformed):
			http.Error(w, "malformed signature", http.StatusBadRequest)
			return
		case err != nil:
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		// Decode body and revoke the key here.
		w.WriteHeader(http.StatusNoContent)
	})

	body := `{"effect":"revoke_key","api_key_id":"key_7d3e"}`
	for _, sig := range []string{
		signature.Sign(secret, time.Now(), []byte(body)),
		signature.Sign("someone-else", time.Now(), []byte(body)),
		"garbage",
	} {
		req := httptest.NewRequest(http.MethodPost, "/hooks/catraca/revoke-key", strings.NewReader(body))
		req.Header.Set(signature.Header, sig)
		rec := httptest.NewRecorder()
		revokeKey.ServeHTTP(rec, req)
		fmt.Println(rec.Code)
	}
	// Output:
	// 204
	// 401
	// 400
}

// A platform posting to Catraca's generic feedback endpoint signs the body it
// sends.
func ExampleSign() {
	body := []byte(`{"account_id":"acct_123","feedback":{"kind":"complaint"}}`)
	req, err := http.NewRequest(http.MethodPost, "https://catraca.example.com/v1/feedback", bytes.NewReader(body))
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signature.Header, signature.Sign("feedback-secret", time.Unix(1760529600, 0), body))
	fmt.Println(req.Header.Get(signature.Header))
	// Output:
	// t=1760529600,v1=408234c16d3bc535d84c75089dbcc4972a14c15efab2053804947f672bc0804e
}
