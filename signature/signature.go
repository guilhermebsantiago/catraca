// Package signature signs and verifies the Catraca-Signature header.
//
// Catraca signs every request it sends with it, effect webhooks and secret
// scanning resolver calls alike, and the generic feedback endpoint
// (POST /v1/feedback) expects it on the requests it receives. A platform
// written in Go can use this package on both sides instead of
// reimplementing the scheme.
//
// The header value is
//
//	t=<unix seconds>,v1=<hex HMAC-SHA256>
//
// where the HMAC is keyed with a secret shared by both sides and computed
// over the timestamp, a period and the raw request body: "<t>.<body>".
// Signing the timestamp with the body means a captured request cannot be
// replayed later with a fresh timestamp, and Verify rejects timestamps too
// far from the receiver's clock.
//
// A header may carry several v1 values, so a sender can sign with an old and
// a new secret while the secret is rotated; Verify accepts the request when
// any of them matches. Keys other than t and v1 are ignored, which leaves
// room for new schemes next to v1.
//
// Rotation works from either side without a moment where valid requests are
// refused. A sender that knows the new and the old secret signs with both
// (SignAll), so a receiver that still knows only the old one accepts its
// requests; a receiver that knows both verifies with either (VerifyAny), so
// a sender may switch whenever it is ready. Verify and Sign are the
// one-secret cases of the two.
package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Header is the HTTP header that carries the signature.
const Header = "Catraca-Signature"

// DefaultTolerance is how far a signature's timestamp may be from the
// receiver's clock when Verify is given no tolerance.
const DefaultTolerance = 5 * time.Minute

// Errors returned by Verify and VerifyAny. Each is returned as is, so
// callers can compare with errors.Is to tell a broken sender (ErrMalformed)
// from a forged or altered request (ErrMismatch) and a replayed or delayed
// one (ErrExpired).
var (
	// ErrEmptySecret means Verify was called without a secret, or
	// VerifyAny without secrets or with an empty one among them.
	ErrEmptySecret = errors.New("signature: empty secret")
	// ErrMalformed means the header could not be parsed: it is empty, lacks
	// t or v1, has two t values, or has a value that is not a number or hex.
	ErrMalformed = errors.New("signature: malformed header")
	// ErrMismatch means no v1 signature in the header matches the body and
	// secret.
	ErrMismatch = errors.New("signature: no v1 signature matches")
	// ErrExpired means the signature matches but its timestamp is further
	// from the current time than the tolerance, so the request may be a
	// replay.
	ErrExpired = errors.New("signature: timestamp outside tolerance")
)

// Sign returns the Header value for body sent at t, signed with secret. Pass
// the exact bytes that will be sent as the request body.
func Sign(secret string, t time.Time, body []byte) string {
	return SignAll([]string{secret}, t, body)
}

// SignAll returns the Header value for body sent at t with one v1 signature
// per secret, in the order given: "t=<unix>,v1=<sig>,v1=<sig>". While a
// secret is rotated, pass the new secret first and the old one after it,
// so a receiver that knows either accepts the request. With a single
// secret it is Sign.
func SignAll(secrets []string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	var b strings.Builder
	b.WriteString("t=" + ts)
	for _, secret := range secrets {
		b.WriteString(",v1=")
		b.WriteString(hex.EncodeToString(mac(secret, ts, body)))
	}
	return b.String()
}

// Verify checks a Header value against the raw request body. It returns nil
// when one of the header's v1 signatures matches and its timestamp is within
// tolerance of the current time (DefaultTolerance when tolerance is zero or
// negative), and otherwise one of the errors above.
//
// Pass the body exactly as received, before any JSON decoding: re-encoded
// JSON does not match.
func Verify(secret, header string, body []byte, tolerance time.Duration) error {
	return verify(secret, header, body, tolerance, time.Now())
}

// VerifyAny is Verify for a receiver that accepts several secrets, the new
// and the old one while a secret is rotated: it returns nil when one of the
// header's v1 signatures matches any of secrets. Every secret must be
// non-empty, since anyone can compute an HMAC keyed with an empty one: an
// empty list, or an empty secret in it, is ErrEmptySecret.
func VerifyAny(secrets []string, header string, body []byte, tolerance time.Duration) error {
	return verifyAny(secrets, header, body, tolerance, time.Now())
}

func verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	return verifyAny([]string{secret}, header, body, tolerance, now)
}

func verifyAny(secrets []string, header string, body []byte, tolerance time.Duration, now time.Time) error {
	if len(secrets) == 0 || slices.Contains(secrets, "") {
		return ErrEmptySecret
	}
	var ts string
	var sigs [][]byte
	seenT := false
	for part := range strings.SplitSeq(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrMalformed
		}
		switch k {
		case "t":
			// Two t values are malformed even when the first is empty.
			if seenT {
				return ErrMalformed
			}
			ts, seenT = v, true
		case "v1":
			sig, err := hex.DecodeString(v)
			if err != nil {
				return ErrMalformed
			}
			sigs = append(sigs, sig)
		}
	}
	if ts == "" || len(sigs) == 0 {
		return ErrMalformed
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrMalformed
	}

	// Every secret is tried against every signature, without stopping at
	// the first match, so the time taken does not tell which secret the
	// request was signed with.
	matched := false
	for _, secret := range secrets {
		expected := mac(secret, ts, body)
		for _, sig := range sigs {
			if hmac.Equal(sig, expected) {
				matched = true
			}
		}
	}
	if !matched {
		return ErrMismatch
	}

	// The timestamp is checked only once the signature matches, so
	// ErrExpired always means an authentic request that arrived too late or
	// too early, never a forgery.
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	if skew := now.Sub(time.Unix(unix, 0)); skew > tolerance || skew < -tolerance {
		return ErrExpired
	}
	return nil
}

// mac is the HMAC-SHA256 of "<ts>.<body>" keyed with secret.
func mac(secret, ts string, body []byte) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(ts))
	h.Write([]byte{'.'})
	h.Write(body)
	return h.Sum(nil)
}
