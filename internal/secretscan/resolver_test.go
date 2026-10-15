package secretscan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const resolverSecret = "resolver-secret"

// platform is a fake resolver endpoint that checks the signature.
func platform(t *testing.T, answer func(w http.ResponseWriter, req map[string]any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !validSignature(r.Header.Get(SignatureHeader), body) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		answer(w, req)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func validSignature(header string, body []byte) bool {
	var ts, v1 string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			v1 = v
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(sec, 0)).Abs() > time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(resolverSecret))
	mac.Write([]byte(ts + "." + string(body)))
	return hmac.Equal([]byte(v1), []byte(hex.EncodeToString(mac.Sum(nil))))
}

var testToken = Token{Raw: "acme_live_abc", SHA256: hashOf("acme_live_abc"), Type: "acme_api_key", URL: "https://github.com/o/r/blob/x/f", Source: "commit"}

func TestHTTPResolverFound(t *testing.T) {
	requests := make(chan map[string]any, 1)
	srv := platform(t, func(w http.ResponseWriter, req map[string]any) {
		requests <- req
		_, _ = w.Write([]byte(`{"api_key_id":"key_123","account_id":"acct_456"}`))
	})
	r, err := NewHTTPResolver(HTTPResolverConfig{URL: srv.URL, Secret: resolverSecret})
	if err != nil {
		t.Fatal(err)
	}
	key, err := r.Resolve(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	if key != (Key{APIKeyID: "key_123", AccountID: "acct_456"}) {
		t.Errorf("key %+v", key)
	}
	got := <-requests
	want := map[string]any{"token_sha256": testToken.SHA256, "type": "acme_api_key", "source": "commit", "url": testToken.URL}
	if len(got) != len(want) {
		t.Errorf("request %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("request[%q] = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["token"]; ok {
		t.Error("raw token sent without SendRawToken")
	}
}

func TestHTTPResolverSendsRawTokenOnlyWhenAsked(t *testing.T) {
	requests := make(chan map[string]any, 1)
	srv := platform(t, func(w http.ResponseWriter, req map[string]any) {
		requests <- req
		_, _ = w.Write([]byte(`{"api_key_id":"key_123"}`))
	})
	r, err := NewHTTPResolver(HTTPResolverConfig{URL: srv.URL, Secret: resolverSecret, SendRawToken: true})
	if err != nil {
		t.Fatal(err)
	}
	key, err := r.Resolve(context.Background(), testToken)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-requests; got["token"] != testToken.Raw || key.AccountID != "" {
		t.Errorf("request %v, key %+v", got, key)
	}
}

func TestHTTPResolverAnswers(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		notFound bool
	}{
		{"not found", http.StatusNotFound, `{"error":"no such key"}`, true},
		{"server error", http.StatusInternalServerError, `boom`, false},
		{"bad JSON", http.StatusOK, `{`, false},
		{"no key id", http.StatusOK, `{"account_id":"acct"}`, false},
		{"redirect", http.StatusFound, ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := platform(t, func(w http.ResponseWriter, _ map[string]any) {
				if tt.status == http.StatusFound {
					w.Header().Set("Location", "https://evil.example.com/")
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			r, err := NewHTTPResolver(HTTPResolverConfig{URL: srv.URL, Secret: resolverSecret})
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.Resolve(context.Background(), testToken)
			if err == nil {
				t.Fatal("want an error")
			}
			if errors.Is(err, ErrNotFound) != tt.notFound {
				t.Errorf("err %v, want not found = %v", err, tt.notFound)
			}
			if strings.Contains(err.Error(), testToken.Raw) {
				t.Errorf("error carries the token: %v", err)
			}
		})
	}
}

func TestHTTPResolverWrongSecretIsRejected(t *testing.T) {
	srv := platform(t, func(w http.ResponseWriter, _ map[string]any) {
		_, _ = w.Write([]byte(`{"api_key_id":"key_123"}`))
	})
	r, err := NewHTTPResolver(HTTPResolverConfig{URL: srv.URL, Secret: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), testToken); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("err %v, want an authentication failure", err)
	}
}

func TestNewHTTPResolverValidatesConfig(t *testing.T) {
	for _, cfg := range []HTTPResolverConfig{
		{Secret: "s"},
		{URL: "ftp://platform/resolve", Secret: "s"},
		{URL: "https:///resolve", Secret: "s"},
		{URL: "https://platform.example.com/resolve"},
	} {
		if _, err := NewHTTPResolver(cfg); err == nil {
			t.Errorf("%+v: want an error", cfg)
		}
	}
}
