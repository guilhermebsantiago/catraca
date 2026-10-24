package signature_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/signature"
)

// The fuzz targets use only the exported API, against the real clock, so
// they keep well away from the edges of the tolerance.

// FuzzSignVerify signs a body and checks that Verify accepts exactly that:
// not another body, not another secret, and not a timestamp outside the
// tolerance.
func FuzzSignVerify(f *testing.F) {
	f.Add("whsec_test_0123456789", []byte(`{"effect":"revoke_key"}`), []byte(`{"effect":"suspend_account"}`), "another-secret", int64(0))
	f.Add("whsec_0123456789abcdef", []byte(`{"effect":"revoke_key","api_key_id":"key_7d3e"}`), []byte(nil), "someone-else", int64(-3600))
	f.Add("s", []byte(""), []byte(" "), "s\x00", int64(299))
	f.Add(strings.Repeat("k", 100), []byte("a.b"), []byte("a.b\n"), "", int64(1<<40))
	f.Fuzz(func(t *testing.T, secret string, body, other []byte, otherSecret string, offset int64) {
		const tolerance = 10 * time.Minute
		now := time.Now()
		header := signature.Sign(secret, now, body)
		err := signature.Verify(secret, header, body, tolerance)
		if secret == "" {
			if !errors.Is(err, signature.ErrEmptySecret) {
				t.Fatalf("Verify with an empty secret = %v, want ErrEmptySecret", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("Verify(Sign(...)) = %v, want nil", err)
		}
		if !bytes.Equal(other, body) {
			if err := signature.Verify(secret, header, other, tolerance); !errors.Is(err, signature.ErrMismatch) {
				t.Errorf("Verify of another body = %v, want ErrMismatch", err)
			}
		}
		// HMAC pads a key with zero bytes and hashes a key longer than a
		// block, so some different secrets are the same key.
		if otherSecret != "" && hmacKey(otherSecret) != hmacKey(secret) {
			if err := signature.Verify(otherSecret, header, body, tolerance); !errors.Is(err, signature.ErrMismatch) {
				t.Errorf("Verify with another secret = %v, want ErrMismatch", err)
			}
		}

		// Signed offset seconds away from now, the signature is accepted
		// well within the tolerance and refused well outside it. The
		// margin covers the clock moving on and the truncation to seconds.
		// Beyond 2^33 seconds the offset would overflow a Duration.
		offset %= 1 << 32
		at := now.Add(time.Duration(offset) * time.Second)
		err = signature.Verify(secret, signature.Sign(secret, at, body), body, tolerance)
		const margin = 5 * time.Second
		switch skew := time.Duration(max(offset, -offset)) * time.Second; {
		case skew < tolerance-margin && err != nil:
			t.Errorf("signed %ds away, within the tolerance: %v", offset, err)
		case skew > tolerance+margin && !errors.Is(err, signature.ErrExpired):
			t.Errorf("signed %ds away, outside the tolerance: %v, want ErrExpired", offset, err)
		}
	})
}

// FuzzVerify checks any header against a body: Verify never panics, and it
// accepts a header only when the header carries the HMAC of its own
// timestamp and the body, a timestamp within the tolerance.
func FuzzVerify(f *testing.F) {
	const secret = "whsec_test_0123456789"
	body := []byte(`{"effect":"revoke_key","decision_id":"d1"}`)
	now := time.Now()
	valid := signature.Sign(secret, now, body)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := valid[len("t="+ts+",v1="):]
	for _, h := range []string{
		valid,
		"t=" + ts + ", v1=" + sig,
		"v1=" + sig + ",t=" + ts,
		signature.Sign("another-secret", now, body) + ",v1=" + sig,
		valid + ",v2=abcd",
		"t=" + ts + ",v1=" + sig + ",t=" + ts,
		"t=,t=" + ts + ",v1=" + sig,
		"t=+" + ts + ",v1=" + sig,
		"t=0" + ts + ",v1=" + sig,
		"t=" + ts + ",v1=" + strings.ToUpper(sig),
		"t=" + ts + ",v1=zz",
		"t=" + ts + ",garbage",
		"t=99999999999999999999,v1=" + sig,
		"",
	} {
		f.Add(h, body)
	}
	f.Fuzz(func(t *testing.T, header string, body []byte) {
		const tolerance = time.Hour
		err := signature.Verify(secret, header, body, tolerance)
		stamps, sigs := parts(header)
		switch {
		case len(stamps) > 1 && !errors.Is(err, signature.ErrMalformed):
			t.Fatalf("Verify of %q, with two t values, = %v, want ErrMalformed", header, err)
		case err == nil && !authentic(secret, stamps, sigs, body, tolerance):
			t.Fatalf("Verify accepted %q for a body it does not sign", header)
		case err != nil && !errors.Is(err, signature.ErrMalformed) && !errors.Is(err, signature.ErrMismatch) && !errors.Is(err, signature.ErrExpired):
			t.Fatalf("Verify = %v, not one of the documented errors", err)
		}
	})
}

// parts returns the values of a header's t and v1 keys.
func parts(header string) (stamps, sigs []string) {
	for part := range strings.SplitSeq(header, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "t="); ok {
			stamps = append(stamps, v)
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "v1="); ok {
			sigs = append(sigs, strings.ToLower(v))
		}
	}
	return stamps, sigs
}

// authentic reports whether a header with these t and v1 values holds one
// timestamp, within tolerance of now, and the HMAC of that timestamp and
// body.
func authentic(secret string, stamps, sigs []string, body []byte, tolerance time.Duration) bool {
	if len(stamps) != 1 {
		return false
	}
	for _, ts := range stamps {
		unix, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			continue
		}
		if skew := time.Since(time.Unix(unix, 0)); skew > tolerance+time.Minute || skew < -tolerance-time.Minute {
			continue
		}
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(ts + "."))
		m.Write(body)
		want := hex.EncodeToString(m.Sum(nil))
		for _, s := range sigs {
			if s == want {
				return true
			}
		}
	}
	return false
}

// hmacKey returns the block HMAC-SHA256 actually keys with for secret.
func hmacKey(secret string) [sha256.BlockSize]byte {
	var k [sha256.BlockSize]byte
	if len(secret) > sha256.BlockSize {
		sum := sha256.Sum256([]byte(secret))
		copy(k[:], sum[:])
	} else {
		copy(k[:], secret)
	}
	return k
}
