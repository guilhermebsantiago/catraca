package hooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Headers sent with every delivery.
const (
	// SignatureHeader carries "t=<unix seconds>,v1=<hex HMAC-SHA256>", where
	// the HMAC is keyed with the hook's secret and computed over
	// "<t>.<body>".
	SignatureHeader = "Catraca-Signature"
	// IdempotencyKeyHeader carries "<decision id>:<effect>". It is the same
	// on every attempt of a delivery: receivers should act on a key once.
	IdempotencyKeyHeader = "Catraca-Idempotency-Key"
	// AttemptHeader carries the attempt number, starting at 1.
	AttemptHeader = "Catraca-Attempt"
)

// DefaultTolerance is how far a signature's timestamp may be from the
// receiver's clock when Verify is given no tolerance.
const DefaultTolerance = 5 * time.Minute

var (
	// ErrMalformedSignature means the signature header could not be parsed.
	ErrMalformedSignature = errors.New("hooks: malformed signature header")
	// ErrSignatureMismatch means no signature in the header matches the body
	// and secret.
	ErrSignatureMismatch = errors.New("hooks: signature does not match")
	// ErrSignatureExpired means the signature's timestamp is outside the
	// tolerance, so the request may be a replay.
	ErrSignatureExpired = errors.New("hooks: signature timestamp outside tolerance")
	// ErrEmptySecret means Verify was called without a secret.
	ErrEmptySecret = errors.New("hooks: empty secret")
)

// Sign returns the SignatureHeader value for body sent at t.
func Sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac(secret, ts, body))
}

// Verify checks a SignatureHeader value against the raw request body, for
// receivers written in Go. It returns nil when one of the header's v1
// signatures matches and its timestamp is within tolerance of the current
// time (DefaultTolerance when tolerance is zero or negative). Pass the body
// exactly as received, before any JSON decoding.
func Verify(secret, header string, body []byte, tolerance time.Duration) error {
	return verify(secret, header, body, tolerance, time.Now())
}

func verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	if secret == "" {
		return ErrEmptySecret
	}
	var ts string
	var sigs [][]byte
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrMalformedSignature
		}
		switch k {
		case "t":
			if ts != "" {
				return ErrMalformedSignature
			}
			ts = v
		case "v1":
			sig, err := hex.DecodeString(v)
			if err != nil {
				return ErrMalformedSignature
			}
			sigs = append(sigs, sig)
		}
		// Other keys are ignored, so new signature schemes can be added
		// next to v1 without breaking receivers.
	}
	if ts == "" || len(sigs) == 0 {
		return ErrMalformedSignature
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrMalformedSignature
	}

	expected := mac(secret, ts, body)
	matched := false
	for _, sig := range sigs {
		if hmac.Equal(sig, expected) {
			matched = true
			break
		}
	}
	if !matched {
		return ErrSignatureMismatch
	}

	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	if skew := now.Sub(time.Unix(unix, 0)); skew > tolerance || skew < -tolerance {
		return ErrSignatureExpired
	}
	return nil
}

// mac is the HMAC-SHA256 of "<ts>.<body>" keyed with secret. The timestamp
// is signed with the body so a captured request cannot be replayed later
// with a fresh timestamp.
func mac(secret, ts string, body []byte) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts))
	h.Write([]byte{'.'})
	h.Write(body)
	return h.Sum(nil)
}
