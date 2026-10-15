package signature

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

const (
	secret   = "whsec_test_0123456789"
	knownMAC = "5333384c6b43e0763a47a540c38f9aba18eda5e7541553c4bdd9956c8c56b492"
)

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

func TestSignTruncatesToSeconds(t *testing.T) {
	body := []byte(`{}`)
	at := time.Unix(1700000000, 0)
	if a, b := Sign(secret, at, body), Sign(secret, at.Add(999*time.Millisecond), body); a != b {
		t.Errorf("signatures within one second differ: %q and %q", a, b)
	}
}

func TestVerify(t *testing.T) {
	now := time.Unix(1700000000, 0)
	body := []byte(`{"effect":"revoke_key","decision_id":"d1"}`)
	valid := Sign(secret, now, body)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := valid[len("t="+ts+",v1="):]
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
		{"valid with spaces", secret, "t=" + ts + ", v1=" + sig, body, time.Minute, now, nil},
		{"v1 before t", secret, "v1=" + sig + ",t=" + ts, body, time.Minute, now, nil},
		{"rotation: one of several v1 matches", secret, other + ",v1=" + sig, body, time.Minute, now, nil},
		{"unknown keys ignored", secret, valid + ",v2=abcd", body, time.Minute, now, nil},
		{"within tolerance", secret, valid, body, time.Minute, now.Add(59 * time.Second), nil},
		{"zero tolerance means default", secret, valid, body, 0, now.Add(4 * time.Minute), nil},
		{"negative tolerance means default", secret, valid, body, -time.Second, now.Add(-4 * time.Minute), nil},
		{"tampered body", secret, valid, []byte(`{"effect":"suspend_account","decision_id":"d1"}`), time.Minute, now, ErrMismatch},
		{"empty body", secret, valid, nil, time.Minute, now, ErrMismatch},
		{"wrong secret", "not-the-secret", valid, body, time.Minute, now, ErrMismatch},
		{"replayed with a new timestamp", secret, "t=1700000500,v1=" + sig, body, time.Hour, now, ErrMismatch},
		{"forged and old is a mismatch", secret, other, body, time.Minute, now.Add(time.Hour), ErrMismatch},
		{"too old", secret, valid, body, time.Minute, now.Add(2 * time.Minute), ErrExpired},
		{"from the future", secret, valid, body, time.Minute, now.Add(-2 * time.Minute), ErrExpired},
		{"default tolerance exceeded", secret, valid, body, 0, now.Add(6 * time.Minute), ErrExpired},
		{"empty header", secret, "", body, time.Minute, now, ErrMalformed},
		{"no timestamp", secret, "v1=" + knownMAC, body, time.Minute, now, ErrMalformed},
		{"no signature", secret, "t=" + ts, body, time.Minute, now, ErrMalformed},
		{"empty timestamp", secret, "t=,v1=" + sig, body, time.Minute, now, ErrMalformed},
		{"bad timestamp", secret, "t=yesterday,v1=" + knownMAC, body, time.Minute, now, ErrMalformed},
		{"two timestamps", secret, valid + ",t=" + ts, body, time.Minute, now, ErrMalformed},
		{"bad hex", secret, "t=" + ts + ",v1=zz", body, time.Minute, now, ErrMalformed},
		{"no equals sign", secret, "t=" + ts + ",garbage", body, time.Minute, now, ErrMalformed},
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
	if err := Verify(secret, Sign(secret, time.Now().Add(-time.Hour), body), body, time.Minute); !errors.Is(err, ErrExpired) {
		t.Errorf("Verify of an hour-old signature = %v, want ErrExpired", err)
	}
}
