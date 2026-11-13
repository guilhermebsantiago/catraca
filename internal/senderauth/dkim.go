package senderauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// minRSABits is the smallest RSA key verifiers may accept (RFC 8301).
const minRSABits = 1024

// DKIMKey is a parsed DKIM key record (RFC 6376 section 3.6.1).
type DKIMKey struct {
	// Revoked is true for a record with an empty p=, which says the key
	// was withdrawn: signatures made with it fail.
	Revoked bool `json:"revoked,omitempty"`
	// Type is the key type, rsa (the default) or ed25519.
	Type string `json:"type,omitempty"`
	// Bits is the size of an RSA key.
	Bits int `json:"bits,omitempty"`
	// Testing is true for t=y: the domain is testing DKIM, and receivers
	// treat failures as if the mail were unsigned.
	Testing bool `json:"testing,omitempty"`
}

// ParseDKIMKey parses the TXT record of a DKIM selector. It fails for a
// record that is not a valid tag list (RFC 6376 section 3.2: a tag without
// =, or one repeated), whose v is not DKIM1 or not first, that has no p
// tag, an unknown key type, or a key that does not decode: base64 of an
// RSA SubjectPublicKeyInfo of at least 1024 bits, or of a 32 byte Ed25519
// key (RFC 8463). An empty p= is not an error: the key is revoked.
func ParseDKIMKey(record string) (DKIMKey, error) {
	tags := map[string]string{}
	for i, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		k, v, ok := strings.Cut(tag, "=")
		if !ok {
			return DKIMKey{}, fmt.Errorf("%q is not a tag=value pair", tag)
		}
		// Tag names are case-sensitive in DKIM.
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, dup := tags[k]; dup {
			return DKIMKey{}, fmt.Errorf("tag %s appears more than once", k)
		}
		if k == "v" && (i != 0 || v != "DKIM1") {
			return DKIMKey{}, fmt.Errorf("v=%s: v must be DKIM1 and the first tag", v)
		}
		tags[k] = v
	}
	key := DKIMKey{Type: "rsa"}
	if k, ok := tags["k"]; ok {
		key.Type = k
	}
	for flag := range strings.SplitSeq(tags["t"], ":") {
		if strings.TrimSpace(flag) == "y" {
			key.Testing = true
		}
	}
	p, ok := tags["p"]
	if !ok {
		return DKIMKey{}, errors.New("the p tag (the public key) is missing")
	}
	// The key may be split by folding whitespace.
	p = strings.Join(strings.Fields(p), "")
	if p == "" {
		key.Revoked = true
		return key, nil
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		// Some signers leave the padding out; verifiers accept it.
		if der, err = base64.RawStdEncoding.DecodeString(p); err != nil {
			return DKIMKey{}, errors.New("p is not valid base64")
		}
	}
	switch key.Type {
	case "rsa":
		pub, err := parseRSAKey(der)
		if err != nil {
			return DKIMKey{}, err
		}
		key.Bits = pub.N.BitLen()
		if key.Bits < minRSABits {
			return DKIMKey{}, fmt.Errorf("the RSA key has %d bits; verifiers reject keys under %d (RFC 8301)", key.Bits, minRSABits)
		}
	case "ed25519":
		if len(der) != ed25519.PublicKeySize {
			return DKIMKey{}, fmt.Errorf("the Ed25519 key is %d bytes, want %d", len(der), ed25519.PublicKeySize)
		}
	default:
		return DKIMKey{}, fmt.Errorf("unknown key type k=%s; want rsa or ed25519", key.Type)
	}
	return key, nil
}

// parseRSAKey decodes an RSA public key: a SubjectPublicKeyInfo, as RFC
// 6376 specifies, or a bare PKCS #1 key, which some signers publish and
// verifiers accept.
func parseRSAKey(der []byte) (*rsa.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("p is not an RSA key")
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}
	return nil, errors.New("p is not a DER-encoded RSA public key")
}

// DKIMReport is what checking a domain's DKIM selectors found.
type DKIMReport struct {
	// State is found when a selector has a usable key; otherwise unknown
	// when a lookup failed or no selector is configured, invalid when a
	// selector's record is malformed, revoked when one has an empty key,
	// and missing when none has a record. Earlier states win.
	State     string         `json:"state"`
	Selectors []DKIMSelector `json:"selectors,omitempty"`
}

// DKIMSelector is what one selector's record held.
type DKIMSelector struct {
	Selector string `json:"selector"`
	// Name is the name looked up: <selector>._domainkey.<domain>.
	Name string `json:"name"`
	// State is found, revoked, missing, invalid or unknown.
	State  string   `json:"state"`
	Record string   `json:"record,omitempty"`
	Key    *DKIMKey `json:"key,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// checkDKIM looks up each selector's key record under domain.
func checkDKIM(ctx context.Context, lookup func(context.Context, string) ([]string, error), domain string, selectors []string) DKIMReport {
	rep := DKIMReport{State: Unknown}
	if len(selectors) == 0 {
		return rep
	}
	states := map[string]bool{}
	for _, sel := range selectors {
		s := DKIMSelector{Selector: sel, Name: sel + "._domainkey." + domain}
		txts, err := lookup(ctx, s.Name)
		switch {
		case isNotFound(err):
			s.State = Missing
		case err != nil:
			s.State, s.Error = Unknown, fmt.Sprintf("looking up %s: %v", s.Name, err)
		case len(txts) > 1:
			// RFC 6376 section 3.6.2.2 leaves the result undefined.
			s.State, s.Error = Invalid, fmt.Sprintf("%d TXT records; a selector must have one", len(txts))
		default:
			s.Record = txts[0]
			key, err := ParseDKIMKey(txts[0])
			switch {
			case err != nil:
				s.State, s.Error = Invalid, err.Error()
			case key.Revoked:
				s.State, s.Key = Revoked, &key
			default:
				s.State, s.Key = Found, &key
			}
		}
		states[s.State] = true
		rep.Selectors = append(rep.Selectors, s)
	}
	for _, st := range []string{Found, Unknown, Invalid, Revoked, Missing} {
		if states[st] {
			rep.State = st
			break
		}
	}
	return rep
}
