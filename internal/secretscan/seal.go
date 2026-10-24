package secretscan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// sealer encrypts raw tokens for the queue, for a Resolver that needs them.
// A reported token is a live credential until the platform revokes it, and
// the queue lives in the audit database, which is backed up, replicated and
// read by people and tools that never need a credential. Sealed, a token in
// a row, a backup or a page of the database file that a delete left behind
// is useless without the key, and the key is never stored: it is derived
// from the resolver's secret, which only the server and the platform hold,
// and the platform receives the raw tokens anyway.
//
// A sealed token is "v1:" and the base64 of a random nonce followed by the
// AES-256-GCM ciphertext. The report key is the additional data, so a
// sealed token copied into another report does not open.
//
// While the secret is rotated, tokens are sealed with the key of the new
// secret and opened with the key of whichever secret opens them, so a
// report that waited in the queue through the rotation still resolves.
type sealer struct {
	// aeads has a cipher per secret, the current one first.
	aeads []cipher.AEAD
}

const sealVersion = "v1:"

// sealInfo separates this key from any other use of the secret, which also
// keys the HMAC of resolver requests.
const sealInfo = "catraca secretscan raw token v1"

var errUnseal = errors.New("secretscan: the stored raw token cannot be decrypted; was secret_scanning.github.resolver.secret changed since it was stored, without keeping the old one in previous_secrets?")

// newSealer returns a sealer that seals with a key derived from secret and
// opens with that key or one derived from any of previous.
func newSealer(secret string, previous ...string) (*sealer, error) {
	s := &sealer{}
	for _, sec := range append([]string{secret}, previous...) {
		if sec == "" {
			return nil, errors.New("secretscan: empty raw token secret")
		}
		key, err := hkdf.Key(sha256.New, []byte(sec), nil, sealInfo, 32)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.aeads = append(s.aeads, aead)
	}
	return s, nil
}

func (s *sealer) seal(raw, reportKey string) string {
	aead := s.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return sealVersion + base64.RawStdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(raw), []byte(reportKey)))
}

func (s *sealer) open(sealed, reportKey string) (string, error) {
	enc, ok := strings.CutPrefix(sealed, sealVersion)
	if !ok {
		return "", errUnseal
	}
	b, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil {
		return "", errUnseal
	}
	for _, aead := range s.aeads {
		n := aead.NonceSize()
		if len(b) < n {
			return "", errUnseal
		}
		// GCM authenticates the ciphertext, so a key other than the one
		// that sealed it fails here rather than returning garbage.
		if raw, err := aead.Open(nil, b[:n], b[n:], []byte(reportKey)); err == nil {
			return string(raw), nil
		}
	}
	return "", errUnseal
}
