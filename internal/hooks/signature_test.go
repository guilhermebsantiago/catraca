package hooks

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

const knownMAC = "5333384c6b43e0763a47a540c38f9aba18eda5e7541553c4bdd9956c8c56b492"

func TestSignKnownValue(t *testing.T) {
	// Computed independently: printf '1700000000.{"effect":"revoke_key"}' |
	// openssl dgst -sha256 -hmac whsec_test_0123456789
	body := []byte(`{"effect":"revoke_key"}`)
	got := Sign(secret, time.Unix(1700000000, 0), body)
	want := "t=1700000000,v1=" + knownMAC
	if got != want {
		t.Errorf("Sign = %q, want %q", got, want)
	}
}

func TestVerify(t *testing.T) {
	now := time.Unix(1700000000, 0)
	body := []byte(`{"effect":"revoke_key","decision_id":"d1"}`)
	valid := Sign(secret, now, body)
	ts := strconv.FormatInt(now.Unix(), 10)
	other := Sign("another-secret", now, body)

	tests := []struct {
		name      string
		secret    string
		header    string
		body      []byte
		tolerance time.Duration
		now       time.Time
		want      error
	}{
		{"valid", secret, valid, body, time.Minute, now, nil},
		{"valid with spaces", secret, "t=" + ts + ", v1=" + valid[len("t="+ts+",v1="):], body, time.Minute, now, nil},
		{"one of several v1 matches", secret, other + ",v1=" + valid[len("t="+ts+",v1="):], body, time.Minute, now, nil},
		{"unknown keys ignored", secret, valid + ",v2=abcd", body, time.Minute, now, nil},
		{"within tolerance", secret, valid, body, time.Minute, now.Add(59 * time.Second), nil},
		{"zero tolerance means default", secret, valid, body, 0, now.Add(4 * time.Minute), nil},
		{"tampered body", secret, valid, []byte(`{"effect":"suspend_account","decision_id":"d1"}`), time.Minute, now, ErrSignatureMismatch},
		{"wrong secret", "not-the-secret", valid, body, time.Minute, now, ErrSignatureMismatch},
		{"replayed with a new timestamp", secret, "t=1700000500,v1=" + valid[len("t="+ts+",v1="):], body, time.Hour, now, ErrSignatureMismatch},
		{"too old", secret, valid, body, time.Minute, now.Add(2 * time.Minute), ErrSignatureExpired},
		{"from the future", secret, valid, body, time.Minute, now.Add(-2 * time.Minute), ErrSignatureExpired},
		{"default tolerance exceeded", secret, valid, body, 0, now.Add(6 * time.Minute), ErrSignatureExpired},
		{"empty header", secret, "", body, time.Minute, now, ErrMalformedSignature},
		{"no timestamp", secret, "v1=" + knownMAC, body, time.Minute, now, ErrMalformedSignature},
		{"no signature", secret, "t=" + ts, body, time.Minute, now, ErrMalformedSignature},
		{"bad timestamp", secret, "t=yesterday,v1=" + knownMAC, body, time.Minute, now, ErrMalformedSignature},
		{"two timestamps", secret, valid + ",t=" + ts, body, time.Minute, now, ErrMalformedSignature},
		{"bad hex", secret, "t=" + ts + ",v1=zz", body, time.Minute, now, ErrMalformedSignature},
		{"no equals sign", secret, "t=" + ts + ",garbage", body, time.Minute, now, ErrMalformedSignature},
		{"empty secret", "", valid, body, time.Minute, now, ErrEmptySecret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verify(tt.secret, tt.header, tt.body, tt.tolerance, tt.now)
			if !errors.Is(err, tt.want) {
				t.Errorf("verify = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyUsesTheClock(t *testing.T) {
	body := []byte(`{}`)
	if err := Verify(secret, Sign(secret, time.Now(), body), body, time.Minute); err != nil {
		t.Errorf("Verify of a fresh signature: %v", err)
	}
	if err := Verify(secret, Sign(secret, time.Now().Add(-time.Hour), body), body, time.Minute); !errors.Is(err, ErrSignatureExpired) {
		t.Errorf("Verify of an hour-old signature = %v, want ErrSignatureExpired", err)
	}
}
