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
type sealer struct {
	aead cipher.AEAD
}

const sealVersion = "v1:"

// sealInfo separates this key from any other use of the secret, which also
// keys the HMAC of resolver requests.
const sealInfo = "catraca secretscan raw token v1"

var errUnseal = errors.New("secretscan: the stored raw token cannot be decrypted; was secret_scanning.github.resolver.secret changed since it was stored?")

func newSealer(secret string) (*sealer, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, sealInfo, 32)
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
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(raw, reportKey string) string {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return sealVersion + base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, []byte(raw), []byte(reportKey)))
}

func (s *sealer) open(sealed, reportKey string) (string, error) {
	enc, ok := strings.CutPrefix(sealed, sealVersion)
	if !ok {
		return "", errUnseal
	}
	b, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil || len(b) < s.aead.NonceSize() {
		return "", errUnseal
	}
	n := s.aead.NonceSize()
	raw, err := s.aead.Open(nil, b[:n], b[n:], []byte(reportKey))
	if err != nil {
		return "", errUnseal
	}
	return string(raw), nil
}
