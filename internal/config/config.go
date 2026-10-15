// Package config loads catraca.yaml, the configuration of the Catraca
// server.
//
// Parsing is strict: an unknown or repeated field is an error with its line
// number, and every problem in the file is reported at once. Values may
// reference environment variables as ${NAME} or ${NAME:-default}, so
// secrets stay out of the file. Fields left out take documented defaults,
// relative paths are resolved against the directory of the file, and the
// result is validated before it is returned. See docs/config.md.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/engine"
	"github.com/guilhermebsantiago/catraca/internal/precision"
)

// Defaults for fields left out of the file.
const (
	DefaultListen          = ":8080"
	DefaultMaxBodyBytes    = 1 << 20
	DefaultShutdownTimeout = 30 * time.Second
	DefaultRulesPath       = "rules/default.yaml"
	DefaultAuditDSN        = "sqlite:catraca.db"
	DefaultHookTimeout     = 10 * time.Second
	DefaultLogLevel        = "info"
	DefaultLogFormat       = "json"
)

// Store backends, the values of store.backend.
const (
	StoreMemory = "memory"
	StoreRedis  = "redis"
)

// Config is the server configuration. The zero value is not useful; get one
// from Load or Parse, which apply the defaults and validate it.
type Config struct {
	Server Server `yaml:"server"`
	Auth   Auth   `yaml:"auth"`
	Rules  Rules  `yaml:"rules"`
	Store  Store  `yaml:"store"`
	Audit  Audit  `yaml:"audit"`
	Engine Engine `yaml:"engine"`
	Gate   Gate   `yaml:"gate"`
	// Hooks are the webhooks that carry out the effects of enforced rules,
	// one per effect name.
	Hooks          []Hook         `yaml:"hooks"`
	Feedback       Feedback       `yaml:"feedback"`
	SecretScanning SecretScanning `yaml:"secret_scanning"`
	Logging        Logging        `yaml:"logging"`

	// File is the path the configuration was read from, or "" for Parse
	// without a file name.
	File string `yaml:"-"`
}

// Server configures the HTTP listener.
type Server struct {
	// Listen is the address to listen on, host:port. Default ":8080".
	Listen string `yaml:"listen"`
	// MaxBodyBytes limits request bodies on the /v1 JSON routes. Default
	// 1 MiB. Feedback and secret scanning routes have their own limits.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
	// ShutdownTimeout bounds a graceful shutdown: draining requests and
	// writing queued decisions. Default 30s.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// Auth configures the bearer tokens the /v1 routes accept.
type Auth struct {
	// Tokens are the accepted API tokens. At least one is required. Several
	// tokens let each client have its own and let a token be rotated.
	Tokens []Token `yaml:"tokens"`
}

// Token is one API token.
type Token struct {
	// Name identifies the token in access logs; the token itself is never
	// logged.
	Name  string `yaml:"name"`
	Token Secret `yaml:"token"`
}

// Rules configures the ruleset.
type Rules struct {
	// Path is the ruleset file. Default "rules/default.yaml".
	Path string `yaml:"path"`
}

// Store configures where signal counters are kept.
type Store struct {
	// Backend is "memory" (the default: one process, counters lost on
	// restart) or "redis" (shared by every instance).
	Backend string `yaml:"backend"`
	Redis   Redis  `yaml:"redis"`
}

// Redis configures the Redis store.
type Redis struct {
	// URL is a redis:// or rediss:// URL, for example
	// "redis://:password@localhost:6379/0".
	URL Secret `yaml:"url"`
	// Prefix is prepended to every key. Default "catraca:".
	Prefix string `yaml:"prefix"`
}

// Audit configures the decision log.
type Audit struct {
	// DSN names the database: "sqlite:/path/to/audit.db", a plain path
	// (SQLite) or a postgres:// URL. Default "sqlite:catraca.db".
	DSN Secret `yaml:"dsn"`
	// EventDetail is how much of each event is kept: "minimal" (the
	// default, no message content) or "full".
	EventDetail string `yaml:"event_detail"`
}

// Engine configures decisions.
type Engine struct {
	// Deadline bounds the signal lookup of one decision. When it expires
	// the decision is made without the missing signals. Default 10ms.
	Deadline time.Duration `yaml:"deadline"`
}

// Gate is the precision gate a rule must clear before it enforces.
type Gate struct {
	// MinLabeled is the labeled matches required. Default 30.
	MinLabeled int `yaml:"min_labeled"`
	// MinPrecision is the required Wilson 95% lower bound. Default 0.9.
	MinPrecision float64 `yaml:"min_precision"`
}

// Precision returns the gate for the precision package.
func (g Gate) Precision() precision.Gate {
	return precision.Gate{MinLabeled: g.MinLabeled, MinPrecision: g.MinPrecision}
}

// Hook is a webhook that carries out one effect.
type Hook struct {
	// Name is the effect, as rules list it under effects: revoke_key,
	// suspend_account, notify, ...
	Name string `yaml:"name"`
	// URL receives a signed POST for each delivery.
	URL string `yaml:"url"`
	// Secret keys the Catraca-Signature header.
	Secret Secret `yaml:"secret"`
	// Timeout bounds one attempt. Default 10s.
	Timeout time.Duration `yaml:"timeout"`
	// Headers are added to every request, for example Authorization.
	Headers map[string]Secret `yaml:"headers"`
}

// Feedback configures the delivery feedback routes. A provider is enabled
// when its section is present.
type Feedback struct {
	SES     *SES     `yaml:"ses"`
	UseSend *UseSend `yaml:"usesend"`
	Generic *Generic `yaml:"generic"`
}

// SES configures POST /v1/feedback/ses.
type SES struct {
	// TopicARNs are the SNS topics accepted. Required.
	TopicARNs []string `yaml:"topic_arns"`
	// AccountTag is the SES message tag holding the account id.
	AccountTag string `yaml:"account_tag"`
	// AccountHeader is the email header holding the account id, the
	// fallback when the tag is missing. One of the two is required.
	AccountHeader string `yaml:"account_header"`
}

// UseSend configures POST /v1/feedback/usesend.
type UseSend struct {
	// Secret is the webhook signing secret shown by useSend. Required.
	Secret Secret `yaml:"secret"`
	// AccountMetadataKey reads the account id from the email's metadata
	// instead of the useSend team id.
	AccountMetadataKey string `yaml:"account_metadata_key"`
}

// Generic configures POST /v1/feedback.
type Generic struct {
	// Secret is the shared secret requests are signed with. Required.
	Secret Secret `yaml:"secret"`
}

// SecretScanning configures leaked key reports.
type SecretScanning struct {
	GitHub GitHub `yaml:"github"`
}

// GitHub configures POST /v1/secret-scanning/github.
type GitHub struct {
	// Enabled turns the endpoint on.
	Enabled bool `yaml:"enabled"`
	// Resolver is the platform endpoint that maps a token to its API key.
	Resolver Resolver `yaml:"resolver"`
	// Feedback answers GitHub with true and false positive labels. Enable
	// it once GitHub has enabled feedback for the partnership.
	Feedback bool `yaml:"feedback"`
	// GitHubToken authenticates the request for GitHub's public keys, to
	// avoid unauthenticated rate limits. A token without scopes is enough.
	GitHubToken Secret `yaml:"github_token"`
	// KeysURL is where GitHub's signing keys are fetched. Default
	// https://api.github.com/meta/public_keys/secret_scanning.
	KeysURL string `yaml:"keys_url"`
}

// Resolver configures the HTTP resolver.
type Resolver struct {
	URL    string `yaml:"url"`
	Secret Secret `yaml:"secret"`
	// SendRawToken adds the raw token to resolver requests, for platforms
	// that cannot look keys up by hash. It requires an https URL.
	SendRawToken bool `yaml:"send_raw_token"`
}

// Logging configures the server's logs.
type Logging struct {
	// Level is debug, info (the default), warn or error.
	Level string `yaml:"level"`
	// Format is json (the default) or text.
	Format string `yaml:"format"`
}

// SlogLevel returns Level as a slog.Level. Level must be valid.
func (l Logging) SlogLevel() slog.Level {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(l.Level))
	return lv
}

// Load reads the configuration file at path, expands environment variables
// from the process environment, applies defaults and validates it. Problems
// in the file are reported as an ErrorList.
func Load(path string) (*Config, error) {
	return LoadWith(path, os.LookupEnv)
}

// LoadWith is Load with environment variables read from lookup.
func LoadWith(path string, lookup LookupFunc) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(data, path, lookup)
}

// Parse parses a configuration. file names it in error messages, and
// relative paths in it are resolved against file's directory; with an empty
// file they are resolved against the working directory. lookup reads
// environment variables; nil means os.LookupEnv.
func Parse(data []byte, file string, lookup LookupFunc) (*Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	cfg := &Config{File: file}
	d := &decoder{file: file, lookup: lookup, lines: map[string]int{}, bad: map[string]bool{}}
	if !d.document(data, cfg) {
		return nil, d.errs.sorted()
	}
	v := &validator{d: d}
	v.explicit(cfg)
	cfg.applyDefaults()
	cfg.resolvePaths(filepath.Dir(file))
	v.config(cfg)
	if len(d.errs) > 0 {
		return nil, d.errs.sorted()
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	if c.Server.MaxBodyBytes == 0 {
		c.Server.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = DefaultShutdownTimeout
	}
	if c.Rules.Path == "" {
		c.Rules.Path = DefaultRulesPath
	}
	if c.Store.Backend == "" {
		c.Store.Backend = StoreMemory
	}
	if c.Audit.DSN == "" {
		c.Audit.DSN = DefaultAuditDSN
	}
	if c.Audit.EventDetail == "" {
		c.Audit.EventDetail = string(audit.EventMinimal)
	}
	if c.Engine.Deadline == 0 {
		c.Engine.Deadline = engine.DefaultDeadline
	}
	if c.Gate.MinLabeled == 0 {
		c.Gate.MinLabeled = precision.DefaultMinLabeled
	}
	if c.Gate.MinPrecision == 0 {
		c.Gate.MinPrecision = precision.DefaultMinPrecision
	}
	for i := range c.Hooks {
		if c.Hooks[i].Timeout == 0 {
			c.Hooks[i].Timeout = DefaultHookTimeout
		}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = DefaultLogLevel
	}
	if c.Logging.Format == "" {
		c.Logging.Format = DefaultLogFormat
	}
}

// resolvePaths makes the ruleset path and a SQLite audit path absolute
// relative to dir, so the server finds them whatever its working directory.
func (c *Config) resolvePaths(dir string) {
	if dir == "" || dir == "." {
		return
	}
	if c.Rules.Path != "" && !filepath.IsAbs(c.Rules.Path) {
		c.Rules.Path = filepath.Join(dir, c.Rules.Path)
	}
	if prefix, path, ok := sqlitePath(c.Audit.DSN.Value()); ok && !filepath.IsAbs(path) && !strings.HasPrefix(path, ":memory:") {
		c.Audit.DSN = Secret(prefix + filepath.Join(dir, path))
	}
}

// sqlitePath splits a SQLite DSN into its scheme prefix and path. ok is
// false for Postgres DSNs.
func sqlitePath(dsn string) (prefix, path string, ok bool) {
	switch {
	case dsn == "":
		return "", "", false
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return "", "", false
	case strings.HasPrefix(dsn, "sqlite://"):
		return "sqlite://", strings.TrimPrefix(dsn, "sqlite://"), true
	case strings.HasPrefix(dsn, "sqlite:"):
		return "sqlite:", strings.TrimPrefix(dsn, "sqlite:"), true
	}
	return "", dsn, true
}

// IsSQLite reports whether the audit DSN names a SQLite database.
func (a Audit) IsSQLite() bool {
	_, _, ok := sqlitePath(a.DSN.Value())
	return ok
}

// SQLitePath returns the file of a SQLite audit DSN, or "" for Postgres.
func (a Audit) SQLitePath() string {
	_, path, _ := sqlitePath(a.DSN.Value())
	return path
}
