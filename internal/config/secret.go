package config

import (
	"encoding/json"
	"log/slog"
)

// redacted is what a Secret prints as.
const redacted = "[redacted]"

// Secret is a configuration value that must not be printed: a token, a
// password or a DSN with credentials. Its String, GoString, LogValue and
// JSON and YAML encodings hide the value, so a Config can be logged or
// dumped without leaking it. Value returns the real value.
type Secret string

// Value returns the secret itself.
func (s Secret) Value() string { return string(s) }

// String returns "[redacted]", or "" for an empty secret.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return redacted
}

// GoString keeps %#v from printing the value.
func (s Secret) GoString() string { return `config.Secret("` + s.String() + `")` }

// LogValue keeps slog from logging the value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// MarshalJSON encodes the redacted form.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// MarshalYAML encodes the redacted form.
func (s Secret) MarshalYAML() (any, error) { return s.String(), nil }
