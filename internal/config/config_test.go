package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testToken  = "tok_0123456789abcdef0123456789abcdef"
	testSecret = "sec_0123456789abcdef0123456789abcdef"
)

// env returns a LookupFunc backed by a map.
func env(vars map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

// minimal is the smallest valid configuration.
const minimal = `
auth:
  tokens:
    - name: platform
      token: ` + testToken + `
`

func mustParse(t *testing.T, yaml string, vars map[string]string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(yaml), "", env(vars))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

// parseErrors parses yaml and returns the error messages, failing when it
// parses.
func parseErrors(t *testing.T, yaml string, vars map[string]string) []string {
	t.Helper()
	_, err := Parse([]byte(yaml), "catraca.yaml", env(vars))
	if err == nil {
		t.Fatal("Parse succeeded, want errors")
	}
	var list ErrorList
	if !errors.As(err, &list) {
		t.Fatalf("error is %T, want ErrorList: %v", err, err)
	}
	msgs := make([]string, len(list))
	for i, e := range list {
		msgs[i] = e.Error()
	}
	return msgs
}

func requireError(t *testing.T, msgs []string, want string) {
	t.Helper()
	for _, m := range msgs {
		if strings.Contains(m, want) {
			return
		}
	}
	t.Errorf("no error contains %q; got:\n  %s", want, strings.Join(msgs, "\n  "))
}

func TestExampleConfig(t *testing.T) {
	cfg, err := LoadWith(filepath.Join("..", "..", "catraca.example.yaml"), env(map[string]string{
		"CATRACA_API_TOKEN":       testToken,
		"CATRACA_HOOK_SECRET":     testSecret,
		"CATRACA_FEEDBACK_SECRET": testSecret,
	}))
	if err != nil {
		t.Fatalf("the example configuration does not load:\n%v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if len(cfg.Auth.Tokens) != 1 || cfg.Auth.Tokens[0].Name != "platform" || cfg.Auth.Tokens[0].Token.Value() != testToken {
		t.Errorf("tokens = %#v", cfg.Auth.Tokens)
	}
	if want := filepath.Join("..", "..", "rules", "default.yaml"); cfg.Rules.Path != want {
		t.Errorf("rules.path = %q, want %q", cfg.Rules.Path, want)
	}
	if want := "sqlite:" + filepath.Join("..", "..", "catraca.db"); cfg.Audit.DSN.Value() != want {
		t.Errorf("audit.dsn = %q, want %q", cfg.Audit.DSN.Value(), want)
	}
	if len(cfg.Hooks) != 1 || cfg.Hooks[0].Name != "revoke_key" || cfg.Hooks[0].Timeout != 10*time.Second {
		t.Errorf("hooks = %#v", cfg.Hooks)
	}
	if cfg.Feedback.Generic == nil || cfg.Feedback.SES != nil || cfg.Feedback.UseSend != nil {
		t.Errorf("feedback = %#v", cfg.Feedback)
	}
	if cfg.SecretScanning.GitHub.Enabled {
		t.Error("secret scanning is enabled")
	}
}

func TestDefaults(t *testing.T) {
	cfg := mustParse(t, minimal, nil)
	checks := []struct {
		name      string
		got, want any
	}{
		{"server.listen", cfg.Server.Listen, ":8080"},
		{"server.max_body_bytes", cfg.Server.MaxBodyBytes, int64(1 << 20)},
		{"server.shutdown_timeout", cfg.Server.ShutdownTimeout, 30 * time.Second},
		{"rules.path", cfg.Rules.Path, "rules/default.yaml"},
		{"store.backend", cfg.Store.Backend, "memory"},
		{"audit.dsn", cfg.Audit.DSN.Value(), "sqlite:catraca.db"},
		{"audit.event_detail", cfg.Audit.EventDetail, "minimal"},
		{"engine.deadline", cfg.Engine.Deadline, 10 * time.Millisecond},
		{"gate.min_labeled", cfg.Gate.MinLabeled, 30},
		{"gate.min_precision", cfg.Gate.MinPrecision, 0.9},
		{"logging.level", cfg.Logging.Level, "info"},
		{"logging.format", cfg.Logging.Format, "json"},
		{"slog level", cfg.Logging.SlogLevel(), slog.LevelInfo},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if cfg.Feedback.SES != nil || cfg.Feedback.UseSend != nil || cfg.Feedback.Generic != nil {
		t.Errorf("feedback providers enabled by default: %#v", cfg.Feedback)
	}
}

func TestFullConfig(t *testing.T) {
	cfg := mustParse(t, `
server:
  listen: 127.0.0.1:9090
  max_body_bytes: 2_097_152
  shutdown_timeout: 1m
auth:
  tokens:
    - name: platform
      token: ${TOKEN}
    - {name: ops.cli, token: "${OPS_TOKEN}"}
rules:
  path: /etc/catraca/rules.yaml
store:
  backend: redis
  redis:
    url: ${REDIS_URL}
    prefix: "prod:"
audit:
  dsn: postgres://catraca:pw@db:5432/catraca
  event_detail: full
engine:
  deadline: 25ms
gate:
  min_labeled: 50
  min_precision: 0.95
hooks:
  - name: revoke_key
    url: https://platform.example/hooks/revoke
    secret: ${HOOK_SECRET}
    headers:
      Authorization: Bearer ${HOOK_AUTH}
  - name: notify
    url: http://notify.internal/catraca
    secret: ${HOOK_SECRET}
    timeout: 3s
feedback:
  ses:
    topic_arns: [arn:aws:sns:us-east-1:111122223333:catraca]
    account_tag: catraca-account
  usesend:
    secret: whsec_abc
    account_metadata_key: account
  generic:
    secret: ${HOOK_SECRET}
secret_scanning:
  github:
    enabled: true
    resolver:
      url: https://platform.example/resolve
      secret: ${HOOK_SECRET}
      send_raw_token: true
    feedback: true
    github_token: ghp_x
    keys_url: http://127.0.0.1:1/keys
logging:
  level: DEBUG
  format: text
`, map[string]string{
		"TOKEN":       testToken,
		"OPS_TOKEN":   testToken + "-ops",
		"REDIS_URL":   "redis://:pw@redis:6379/1",
		"HOOK_SECRET": testSecret,
		"HOOK_AUTH":   "abc",
	})
	if cfg.Server.Listen != "127.0.0.1:9090" || cfg.Server.MaxBodyBytes != 2<<20 || cfg.Server.ShutdownTimeout != time.Minute {
		t.Errorf("server = %#v", cfg.Server)
	}
	if len(cfg.Auth.Tokens) != 2 || cfg.Auth.Tokens[1].Name != "ops.cli" {
		t.Errorf("tokens = %#v", cfg.Auth.Tokens)
	}
	if cfg.Store.Backend != StoreRedis || cfg.Store.Redis.URL.Value() != "redis://:pw@redis:6379/1" || cfg.Store.Redis.Prefix != "prod:" {
		t.Errorf("store = %#v", cfg.Store)
	}
	if cfg.Audit.IsSQLite() || cfg.Audit.EventDetail != "full" {
		t.Errorf("audit = %#v", cfg.Audit)
	}
	if cfg.Engine.Deadline != 25*time.Millisecond || cfg.Gate.MinLabeled != 50 || cfg.Gate.MinPrecision != 0.95 {
		t.Errorf("engine/gate = %#v %#v", cfg.Engine, cfg.Gate)
	}
	if g := cfg.Gate.Precision(); g.MinLabeled != 50 || g.MinPrecision != 0.95 {
		t.Errorf("precision gate = %#v", g)
	}
	if h := cfg.Hooks[0]; h.Timeout != DefaultHookTimeout || h.Headers["Authorization"].Value() != "Bearer abc" {
		t.Errorf("hooks[0] = %#v", h)
	}
	if cfg.Hooks[1].Timeout != 3*time.Second {
		t.Errorf("hooks[1].timeout = %v", cfg.Hooks[1].Timeout)
	}
	if cfg.Feedback.SES == nil || cfg.Feedback.SES.AccountTag != "catraca-account" || cfg.Feedback.UseSend.AccountMetadataKey != "account" {
		t.Errorf("feedback = %#v", cfg.Feedback)
	}
	gh := cfg.SecretScanning.GitHub
	if !gh.Enabled || !gh.Feedback || !gh.Resolver.SendRawToken || gh.KeysURL != "http://127.0.0.1:1/keys" || gh.GitHubToken.Value() != "ghp_x" {
		t.Errorf("github = %#v", gh)
	}
	if cfg.Logging.SlogLevel() != slog.LevelDebug {
		t.Errorf("level = %v", cfg.Logging.SlogLevel())
	}
}

func TestEmptyFileNeedsTokens(t *testing.T) {
	msgs := parseErrors(t, "", nil)
	if len(msgs) != 1 {
		t.Fatalf("errors = %q", msgs)
	}
	requireError(t, msgs, "catraca.yaml: auth.tokens: at least one API token is required")
}

func TestUnknownFields(t *testing.T) {
	msgs := parseErrors(t, `server:
  listn: ":8080"
auth:
  tokens:
    - name: platform
      token: `+testToken+`
      scope: all
stor:
  backend: memory
feedback:
  generic:
    secrets: x
`, nil)
	for _, want := range []string{
		`catraca.yaml:2: server.listn: unknown field (did you mean listen?)`,
		`catraca.yaml:7: auth.tokens[0].scope: unknown field`,
		`catraca.yaml:8: stor: unknown field (did you mean store?)`,
		`catraca.yaml:12: feedback.generic.secrets: unknown field (did you mean secret?)`,
	} {
		requireError(t, msgs, want)
	}
	// The generic section has an unknown field, not a missing secret too.
	for _, m := range msgs {
		if strings.Contains(m, "feedback.generic.secret: is required") {
			t.Errorf("unexpected follow-up error %q", m)
		}
	}
}

func TestErrorsAreSortedByLine(t *testing.T) {
	_, err := Parse([]byte(`logging:
  level: loud
server:
  listen: nope
`), "c.yaml", nil)
	var list ErrorList
	if !errors.As(err, &list) {
		t.Fatalf("err = %v", err)
	}
	for i := 1; i < len(list); i++ {
		if prev, cur := list[i-1].Line, list[i].Line; prev == 0 || (cur != 0 && prev > cur) {
			t.Fatalf("errors out of order, want by line with unpositioned ones last:\n%v", err)
		}
	}
	if !strings.HasPrefix(err.Error(), "c.yaml:2: logging.level:") {
		t.Errorf("first error = %q", err.Error())
	}
}

func TestTypeErrors(t *testing.T) {
	msgs := parseErrors(t, `server:
  max_body_bytes: lots
  shutdown_timeout: 30
auth:
  tokens:
    - name: [platform]
      token: `+testToken+`
hooks: {}
secret_scanning:
  github:
    enabled: yes
gate:
  min_precision: high
`, nil)
	for _, want := range []string{
		`catraca.yaml:2: server.max_body_bytes: want an integer, got "lots"`,
		`catraca.yaml:3: server.shutdown_timeout: want a duration such as 10ms, 30s or 2h, got "30"`,
		`catraca.yaml:6: auth.tokens[0].name: want a string, got a list`,
		`catraca.yaml:8: hooks: want a list, got a mapping`,
		`catraca.yaml:11: secret_scanning.github.enabled: want true or false, got "yes"`,
		`catraca.yaml:13: gate.min_precision: want a number, got "high"`,
	} {
		requireError(t, msgs, want)
	}
}

func TestRepeatedAndMergeKeys(t *testing.T) {
	msgs := parseErrors(t, minimal+`
logging:
  level: info
  level: debug
base: &base {level: info}
`, nil)
	requireError(t, msgs, "catraca.yaml:9: logging.level: set twice")
	requireError(t, msgs, "base: unknown field")

	msgs = parseErrors(t, minimal+`
x: &x {format: text}
logging:
  <<: *x
`, nil)
	requireError(t, msgs, "YAML merge keys (<<) are not supported")
}

func TestSyntaxError(t *testing.T) {
	msgs := parseErrors(t, "server:\n  listen: \"unterminated\n", nil)
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "catraca.yaml:") {
		t.Fatalf("errors = %q", msgs)
	}
	msgs = parseErrors(t, "- a\n- b\n", nil)
	requireError(t, msgs, "catraca.yaml:1: the configuration must be a mapping of settings")
}

func TestEnvironmentInConfig(t *testing.T) {
	cfg := mustParse(t, `
server:
  listen: ${HOST:-127.0.0.1}:${PORT}
  max_body_bytes: ${MAX_BODY:-4096}
auth:
  tokens:
    - name: platform
      token: ${TOKEN}
store:
  redis:
    prefix: "$${not_expanded}:"
logging:
  level: '${LEVEL:-warn}'
`, map[string]string{"PORT": "9000", "TOKEN": "a: b # not a comment, $x {y}"})
	if cfg.Server.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.MaxBodyBytes != 4096 {
		t.Errorf("max_body_bytes = %d", cfg.Server.MaxBodyBytes)
	}
	if got := cfg.Auth.Tokens[0].Token.Value(); got != "a: b # not a comment, $x {y}" {
		t.Errorf("token = %q: a value from the environment must not be parsed as YAML", got)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("level = %q", cfg.Logging.Level)
	}
	if cfg.Store.Redis.Prefix != "${not_expanded}:" {
		t.Errorf("prefix = %q", cfg.Store.Redis.Prefix)
	}

	msgs := parseErrors(t, `
server:
  listen: ${LISTEN}
auth:
  tokens:
    - name: platform
      token: ${TOKEN}
logging:
  format: "${FORMAT"
`, map[string]string{"TOKEN": testToken})
	requireError(t, msgs, "catraca.yaml:3: server.listen: environment variable LISTEN is not set (write ${LISTEN:-default} to make it optional)")
	requireError(t, msgs, "catraca.yaml:9: logging.format: unterminated ${")
	for _, m := range msgs {
		if strings.Contains(m, "server.listen: want host:port") {
			t.Errorf("a variable that failed to expand was validated too: %q", m)
		}
	}
}

func TestExpand(t *testing.T) {
	lookup := env(map[string]string{"A": "alpha", "EMPTY": "", "N_1": "one"})
	tests := []struct {
		in, want, err string
	}{
		{in: "plain", want: "plain"},
		{in: "${A}", want: "alpha"},
		{in: "x-${A}-${N_1}-y", want: "x-alpha-one-y"},
		{in: "${MISSING:-fallback}", want: "fallback"},
		{in: "${EMPTY:-fallback}", want: "fallback"},
		{in: "${EMPTY}", want: ""},
		{in: "${MISSING:-}", want: ""},
		{in: "${A:-unused}", want: "alpha"},
		{in: "${MISSING:-a:-b}", want: "a:-b"},
		{in: "pa$$word $5 $A", want: "pa$$word $5 $A"},
		{in: "$${A}", want: "${A}"},
		{in: "$$${A}", want: "$${A}"},
		{in: "${MISSING}", err: "environment variable MISSING is not set"},
		{in: "${A", err: "unterminated ${"},
		{in: "${}", err: `"" is not a valid environment variable name`},
		{in: "${1A}", err: `"1A" is not a valid environment variable name`},
		{in: "${A-b}", err: `"A-b" is not a valid environment variable name`},
	}
	for _, tt := range tests {
		got, err := expand(tt.in, lookup)
		switch {
		case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
			t.Errorf("expand(%q) error = %v, want %q", tt.in, err, tt.err)
		case tt.err == "" && err != nil:
			t.Errorf("expand(%q) error = %v", tt.in, err)
		case tt.err == "" && got != tt.want:
			t.Errorf("expand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"listen", "server: {listen: localhost}", "server.listen: want host:port"},
		{"listen port", "server: {listen: 'localhost:'}", "server.listen: the port is missing"},
		{"body size", "server: {max_body_bytes: 0}", "server.max_body_bytes: must be at least 1024 bytes, got 0"},
		{"shutdown", "server: {shutdown_timeout: 0s}", "server.shutdown_timeout: must be a positive duration"},
		{"deadline", "engine: {deadline: -1ms}", "engine.deadline: must be a positive duration, got -1ms"},
		{"min labeled", "gate: {min_labeled: 0}", "gate.min_labeled: must be at least 1, got 0"},
		{"min precision", "gate: {min_precision: 1.5}", "gate.min_precision: must be greater than 0 and at most 1, got 1.5"},
		{"store backend", "store: {backend: etcd}", `store.backend: want memory or redis, got "etcd"`},
		{"redis url", "store: {backend: redis}", "store.redis.url: is required with backend: redis"},
		{"redis scheme", "store: {backend: redis, redis: {url: 'http://x'}}", "store.redis.url: want a redis://, rediss:// or unix:// URL"},
		{"redis without backend", "store: {redis: {url: 'redis://x'}}", "store.redis.url: is set but store.backend is memory"},
		{"event detail", "audit: {event_detail: some}", `audit.event_detail: want minimal or full, got "some"`},
		{"sqlite path", "audit: {dsn: 'sqlite:'}", "audit.dsn: the SQLite path is empty"},
		{"hook name", "hooks: [{name: Revoke-Key, url: 'https://x', secret: " + testSecret + "}]", "hooks[0].name: must be lowercase letters"},
		{"hook name required", "hooks: [{url: 'https://x', secret: " + testSecret + "}]", "hooks[0].name: is required"},
		{"hook duplicate", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + "}, {name: a, url: 'https://y', secret: " + testSecret + "}]", "hooks[1].name: another hook already carries out a"},
		{"hook url", "hooks: [{name: a, url: 'ftp://x', secret: " + testSecret + "}]", `hooks[0].url: want an absolute http or https URL, got "ftp://x"`},
		{"hook secret", "hooks: [{name: a, url: 'https://x', secret: short}]", "hooks[0].secret: is 5 characters; use at least 16"},
		{"hook timeout", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", timeout: 0s}]", "hooks[0].timeout: must be a positive duration"},
		{"hook header", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", headers: {Catraca-Signature: x}}]", "hooks[0].headers.Catraca-Signature: Catraca-* headers are set by Catraca"},
		{"ses topics", "feedback: {ses: {account_tag: t}}", "feedback.ses.topic_arns: at least one SNS topic ARN is required"},
		{"ses arn", "feedback: {ses: {topic_arns: [catraca], account_tag: t}}", `feedback.ses.topic_arns[0]: want an SNS topic ARN`},
		{"ses account", "feedback: {ses: {topic_arns: ['arn:aws:sns:us-east-1:1:t']}}", "feedback.ses: set account_tag, account_header or both"},
		{"usesend secret", "feedback: {usesend: {}}", "feedback.usesend.secret: is required"},
		{"generic secret", "feedback:\n  generic:\n", "feedback.generic.secret: is required"},
		{"github resolver", "secret_scanning: {github: {enabled: true}}", "secret_scanning.github.resolver.url: is required"},
		{"github resolver secret", "secret_scanning: {github: {enabled: true, resolver: {url: 'https://r'}}}", "secret_scanning.github.resolver.secret: is required"},
		{"github raw token", "secret_scanning: {github: {enabled: true, resolver: {url: 'http://r', secret: " + testSecret + ", send_raw_token: true}}}", "secret_scanning.github.resolver.send_raw_token: sends live credentials, so the resolver URL must be https"},
		{"github keys url", "secret_scanning: {github: {enabled: true, resolver: {url: 'https://r', secret: " + testSecret + "}, keys_url: nope}}", "secret_scanning.github.keys_url: want an absolute http or https URL"},
		{"log level", "logging: {level: loud}", `logging.level: want debug, info, warn or error, got "loud"`},
		{"log format", "logging: {format: xml}", `logging.format: want json or text, got "xml"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireError(t, parseErrors(t, minimal+tt.yaml+"\n", nil), tt.want)
		})
	}
}

func TestDisabledGitHubIsNotValidated(t *testing.T) {
	mustParse(t, minimal+"secret_scanning: {github: {enabled: false, resolver: {url: nope}}}\n", nil)
}

func TestTokenValidation(t *testing.T) {
	msgs := parseErrors(t, `auth:
  tokens:
    - name: a
      token: short
    - name: a
      token: `+testToken+`
    - name: "b c"
      token: `+testToken+`
    - token: " `+testToken+`"
`, nil)
	for _, want := range []string{
		"catraca.yaml:4: auth.tokens[0].token: is 5 characters; use at least 16 random characters",
		`catraca.yaml:5: auth.tokens[1].name: "a" is used by another token`,
		`catraca.yaml:7: auth.tokens[2].name: must be letters, digits, '.', '_' and '-', got "b c"`,
		"catraca.yaml:8: auth.tokens[2].token: the same token is configured twice",
		"auth.tokens[3].name: is required",
		"catraca.yaml:9: auth.tokens[3].token: has leading or trailing whitespace",
	} {
		requireError(t, msgs, want)
	}
}

func TestRelativePaths(t *testing.T) {
	dir := filepath.Join("etc", "catraca")
	file := filepath.Join(dir, "catraca.yaml")
	tests := []struct {
		dsn, want string
	}{
		{"", "sqlite:" + filepath.Join(dir, "catraca.db")},
		{"audit.db", filepath.Join(dir, "audit.db")},
		{"sqlite://data/audit.db", "sqlite://" + filepath.Join(dir, "data", "audit.db")},
		{"sqlite::memory:", "sqlite::memory:"},
		{"postgres://u:p@db/catraca", "postgres://u:p@db/catraca"},
	}
	for _, tt := range tests {
		yaml := minimal + "rules: {path: my-rules.yaml}\n"
		if tt.dsn != "" {
			yaml += fmt.Sprintf("audit: {dsn: %q}\n", tt.dsn)
		}
		cfg, err := Parse([]byte(yaml), file, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(dir, "my-rules.yaml"); cfg.Rules.Path != want {
			t.Errorf("rules.path = %q, want %q", cfg.Rules.Path, want)
		}
		if got := cfg.Audit.DSN.Value(); got != tt.want {
			t.Errorf("dsn %q resolved to %q, want %q", tt.dsn, got, tt.want)
		}
	}

	abs, err := filepath.Abs("rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(minimal+fmt.Sprintf("rules: {path: %q}\n", abs)), file, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules.Path != abs {
		t.Errorf("absolute rules.path changed to %q", cfg.Rules.Path)
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	cfg := mustParse(t, minimal+`
store:
  backend: redis
  redis: {url: "redis://:hunter2hunter2@redis:6379"}
hooks:
  - {name: revoke_key, url: "https://x", secret: `+testSecret+`, headers: {Authorization: "Bearer hook-token-value"}}
`, nil)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("config", "token", cfg.Auth.Tokens[0].Token, "hooks", cfg.Hooks)
	js, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{
		"%v":   fmt.Sprintf("%v", cfg),
		"%+v":  fmt.Sprintf("%+v", cfg),
		"%#v":  fmt.Sprintf("%#v", cfg),
		"json": string(js),
		"slog": logged.String(),
	}
	for format, out := range outputs {
		for _, secret := range []string{testToken, testSecret, "hunter2", "hook-token-value"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output contains a secret: %s", format, out)
			}
		}
	}
	if !strings.Contains(outputs["json"], redacted) {
		t.Errorf("json output has no redaction marker: %s", outputs["json"])
	}
	if Secret("").String() != "" {
		t.Error("an empty secret should print as empty")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil || !strings.Contains(err.Error(), "nope.yaml") {
		t.Fatalf("err = %v", err)
	}
}
