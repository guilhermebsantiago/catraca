package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/hooks"
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

func TestTokenScopes(t *testing.T) {
	cfg := mustParse(t, `auth:
  tokens:
    - name: send-path
      token: `+testToken+`
      scopes: [decide]
    - name: ops
      token: `+testSecret+`
      previous_tokens: [`+testSecret+`-old]
      scopes: [read, label, admin]
    - name: legacy
      token: `+testToken+`-legacy
`, nil)
	toks := cfg.Auth.Tokens
	if !slices.Equal(toks[0].Scopes, []string{"decide"}) || !slices.Equal(toks[1].Scopes, []string{"read", "label", "admin"}) {
		t.Errorf("scopes = %q and %q", toks[0].Scopes, toks[1].Scopes)
	}
	// Without the key a token has every scope, as before scopes existed.
	if toks[2].Scopes != nil {
		t.Errorf("a token without scopes has %q, want nil for every scope", toks[2].Scopes)
	}

	msgs := parseErrors(t, `auth:
  tokens:
    - name: a
      token: `+testToken+`
      scopes: [decide, write, decide]
    - name: b
      token: `+testSecret+`
      scopes: []
    - name: c
      token: `+testToken+`-c
      scopes:
    - name: d
      token: `+testToken+`-d
      scopes: [Read]
`, nil)
	for _, want := range []string{
		`catraca.yaml:5: auth.tokens[0].scopes[1]: unknown scope "write": use decide, read, label, admin`,
		`catraca.yaml:5: auth.tokens[0].scopes[2]: "decide" is listed twice`,
		"catraca.yaml:8: auth.tokens[1].scopes: is empty: list at least one of decide, read, label, admin, or remove the key for every scope",
		"catraca.yaml:11: auth.tokens[2].scopes: is empty",
		`catraca.yaml:14: auth.tokens[3].scopes[0]: unknown scope "Read"`,
	} {
		requireError(t, msgs, want)
	}
}

// requireSplitTokens checks that a shipped configuration gives the send
// path a token that only decides, and everything else to another token.
func requireSplitTokens(t *testing.T, what string, cfg *Config) {
	t.Helper()
	toks := cfg.Auth.Tokens
	if len(toks) != 2 || toks[0].Name != "send-path" || toks[0].Token.Value() != testToken || !slices.Equal(toks[0].Scopes, []string{"decide"}) ||
		toks[1].Name != "ops" || !slices.Equal(toks[1].Scopes, TokenScopes) {
		t.Errorf("%s: tokens = %#v, want send-path with [decide] and ops with every scope", what, toks)
	}
}

func TestExampleConfig(t *testing.T) {
	cfg, err := LoadWith(filepath.Join("..", "..", "catraca.example.yaml"), env(map[string]string{
		"CATRACA_API_TOKEN":       testToken,
		"CATRACA_OPS_TOKEN":       testToken + "-ops",
		"CATRACA_HOOK_SECRET":     testSecret,
		"CATRACA_FEEDBACK_SECRET": testSecret,
	}))
	if err != nil {
		t.Fatalf("the example configuration does not load:\n%v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	requireSplitTokens(t, "the example", cfg)
	if want := filepath.Join("..", "..", "rules", "default.yaml"); cfg.Rules.Path != want {
		t.Errorf("rules.path = %q, want %q", cfg.Rules.Path, want)
	}
	if want := "sqlite:" + filepath.Join("..", "..", "catraca.db"); cfg.Audit.DSN.Value() != want {
		t.Errorf("audit.dsn = %q, want %q", cfg.Audit.DSN.Value(), want)
	}
	// A hook enabled out of the box would retry deliveries to a placeholder
	// URL after the README's quick start.
	if len(cfg.Hooks) != 0 {
		t.Errorf("hooks = %#v, want none until one is uncommented", cfg.Hooks)
	}
	if cfg.Feedback.Generic == nil || cfg.Feedback.SES != nil || cfg.Feedback.UseSend != nil {
		t.Errorf("feedback = %#v", cfg.Feedback)
	}
	if cfg.SecretScanning.GitHub.Enabled {
		t.Error("secret scanning is enabled")
	}
}

// TestExampleConfigHook keeps the commented-out hook of the example valid:
// uncommented, it loads.
func TestExampleConfigHook(t *testing.T) {
	path := filepath.Join("..", "..", "catraca.example.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	in := false
	for i, line := range lines {
		if line == "# hooks:" {
			in = true
		} else if in && !strings.HasPrefix(line, "# ") {
			in = false
		}
		if in {
			lines[i] = strings.TrimPrefix(line, "# ")
		}
	}
	cfg, err := Parse([]byte(strings.Join(lines, "\n")), path, env(map[string]string{
		"CATRACA_API_TOKEN":       testToken,
		"CATRACA_OPS_TOKEN":       testToken + "-ops",
		"CATRACA_HOOK_SECRET":     testSecret,
		"CATRACA_FEEDBACK_SECRET": testSecret,
		"CATRACA_REVOKE_KEY_URL":  "https://platform.example/hooks/catraca/revoke-key",
	}))
	if err != nil {
		t.Fatalf("the example configuration with its hook uncommented does not load:\n%v", err)
	}
	if len(cfg.Hooks) != 1 || cfg.Hooks[0].Name != "revoke_key" || cfg.Hooks[0].Timeout != 10*time.Second {
		t.Errorf("hooks = %#v", cfg.Hooks)
	}
}

// TestDeployConfigs keeps the configurations in deploy/ valid: the one
// baked into the image and the one compose.yaml mounts.
func TestDeployConfigs(t *testing.T) {
	vars := env(map[string]string{"CATRACA_API_TOKEN": testToken, "CATRACA_OPS_TOKEN": testToken + "-ops", "CATRACA_FEEDBACK_SECRET": testSecret})
	for file, want := range map[string]time.Duration{"catraca.yaml": 5 * time.Second, "catraca.compose.yaml": 0} {
		cfg, err := LoadWith(filepath.Join("..", "..", "deploy", file), vars)
		if err != nil {
			t.Errorf("deploy/%s does not load:\n%v", file, err)
			continue
		}
		requireSplitTokens(t, "deploy/"+file, cfg)
		if cfg.Server.DrainDelay != want {
			t.Errorf("deploy/%s: drain_delay = %v, want %v", file, cfg.Server.DrainDelay, want)
		}
		if cfg.Rules.WatchInterval != DefaultWatchInterval || cfg.Gate.OnLoad != GateEnforce {
			t.Errorf("deploy/%s: rules = %+v, gate = %+v; want the watch and the gate on load at their defaults", file, cfg.Rules, cfg.Gate)
		}
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
		{"server.drain_delay", cfg.Server.DrainDelay, 5 * time.Second},
		{"server.admin_addr", cfg.Server.AdminAddr, ""},
		{"rules.path", cfg.Rules.Path, "rules/default.yaml"},
		{"rules.watch_interval", cfg.Rules.WatchInterval, 5 * time.Second},
		{"gate.on_load", cfg.Gate.OnLoad, "enforce"},
		{"store.backend", cfg.Store.Backend, "memory"},
		{"audit.dsn", cfg.Audit.DSN.Value(), "sqlite:catraca.db"},
		{"audit.event_detail", cfg.Audit.EventDetail, "minimal"},
		{"audit.retention", cfg.Audit.Retention, time.Duration(0)},
		{"audit.labeled_retention", cfg.Audit.LabeledRetention, time.Duration(0)},
		{"audit.max_open_conns", cfg.Audit.MaxOpenConns, 10},
		{"audit.max_idle_conns", cfg.Audit.MaxIdleConns, 10},
		{"audit.conn_max_lifetime", cfg.Audit.ConnMaxLifetime, 30 * time.Minute},
		{"audit.conn_max_idle_time", cfg.Audit.ConnMaxIdleTime, 5 * time.Minute},
		{"engine.deadline", cfg.Engine.Deadline, 10 * time.Millisecond},
		{"engine.dispatch_timeout", cfg.Engine.DispatchTimeout, 10 * time.Millisecond},
		{"outbox.workers", cfg.Outbox.Workers, 16},
		{"engine.max_future_skew", cfg.Engine.MaxFutureSkew, 5 * time.Second},
		{"engine.max_event_age", cfg.Engine.MaxEventAge, 168 * time.Hour},
		{"engine.dedupe_ttl", cfg.Engine.DedupeTTL, 10 * time.Minute},
		{"gate.min_labeled", cfg.Gate.MinLabeled, 30},
		{"gate.min_precision", cfg.Gate.MinPrecision, 0.9},
		{"secret_scanning.github.max_attempts", cfg.SecretScanning.GitHub.MaxAttempts, 1000},
		{"secret_scanning.github.max_age", cfg.SecretScanning.GitHub.MaxAge, 24 * time.Hour},
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
  admin_addr: 127.0.0.1:9091
  drain_delay: 10s
  max_body_bytes: 2_097_152
  shutdown_timeout: 1m
auth:
  tokens:
    - name: platform
      token: ${TOKEN}
    - {name: ops.cli, token: "${OPS_TOKEN}"}
rules:
  path: /etc/catraca/rules.yaml
  watch_interval: 30s
store:
  backend: redis
  redis:
    url: ${REDIS_URL}
    prefix: "prod:"
audit:
  dsn: postgres://catraca:pw@db:5432/catraca
  event_detail: full
  retention: 2160h
  labeled_retention: 17520h
  max_open_conns: 20
  conn_max_lifetime: 1h
  conn_max_idle_time: 1m
engine:
  deadline: 25ms
  dispatch_timeout: 50ms
  max_future_skew: 30s
  max_event_age: 72h
  dedupe_ttl: 1h
gate:
  min_labeled: 50
  min_precision: 0.95
  on_load: warn
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
    concurrency: 8
    max_attempts: 30
    max_age: 72h
outbox:
  workers: 32
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
    max_attempts: 50
    max_age: 72h
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
	if cfg.Server.Listen != "127.0.0.1:9090" || cfg.Server.AdminAddr != "127.0.0.1:9091" || cfg.Server.DrainDelay != 10*time.Second || cfg.Server.MaxBodyBytes != 2<<20 || cfg.Server.ShutdownTimeout != time.Minute {
		t.Errorf("server = %#v", cfg.Server)
	}
	if len(cfg.Auth.Tokens) != 2 || cfg.Auth.Tokens[1].Name != "ops.cli" {
		t.Errorf("tokens = %#v", cfg.Auth.Tokens)
	}
	if cfg.Store.Backend != StoreRedis || cfg.Store.Redis.URL.Value() != "redis://:pw@redis:6379/1" || cfg.Store.Redis.Prefix != "prod:" || cfg.Store.Redis.Mode != "standalone" {
		t.Errorf("store = %#v", cfg.Store)
	}
	if cfg.Audit.IsSQLite() || cfg.Audit.EventDetail != "full" {
		t.Errorf("audit = %#v", cfg.Audit)
	}
	opts := cfg.Audit.Options()
	wantPool := audit.Pool{MaxOpen: 20, MaxIdle: 20, MaxLifetime: time.Hour, MaxIdleTime: time.Minute}
	if opts.EventMode != audit.EventFull || opts.Retention != 90*24*time.Hour || opts.LabeledRetention != 2*365*24*time.Hour ||
		opts.Pool != wantPool {
		t.Errorf("audit options = %+v", opts)
	}
	if cfg.Engine.Deadline != 25*time.Millisecond || cfg.Engine.DispatchTimeout != 50*time.Millisecond ||
		cfg.Engine.MaxFutureSkew != 30*time.Second || cfg.Engine.MaxEventAge != 72*time.Hour ||
		cfg.Engine.DedupeTTL != time.Hour || cfg.Gate.MinLabeled != 50 || cfg.Gate.MinPrecision != 0.95 || cfg.Gate.OnLoad != GateWarn {
		t.Errorf("engine/gate = %#v %#v", cfg.Engine, cfg.Gate)
	}
	if cfg.Rules.WatchInterval != 30*time.Second {
		t.Errorf("rules = %#v", cfg.Rules)
	}
	if cfg.Outbox.Workers != 32 {
		t.Errorf("outbox = %#v", cfg.Outbox)
	}
	if g := cfg.Gate.Precision(); g.MinLabeled != 50 || g.MinPrecision != 0.95 {
		t.Errorf("precision gate = %#v", g)
	}
	if h := cfg.Hooks[0]; h.Timeout != DefaultHookTimeout || h.Headers["Authorization"].Value() != "Bearer abc" ||
		h.Concurrency != 4 || h.MaxAttempts != 15 || h.MaxAge != 24*time.Hour {
		t.Errorf("hooks[0] = %#v", h)
	}
	want := hooks.Hook{Name: "notify", URL: "http://notify.internal/catraca", Secret: testSecret, Timeout: 3 * time.Second,
		Headers: map[string]string{}, Concurrency: 8, MaxAttempts: 30, MaxAge: 72 * time.Hour}
	if h := cfg.Hooks[1].Options(); !reflect.DeepEqual(h, want) {
		t.Errorf("hooks[1].Options() = %#v, want %#v", h, want)
	}
	if h := cfg.Hooks[0].Options(); h.Headers["Authorization"] != "Bearer abc" || h.Secret != testSecret {
		t.Errorf("hooks[0].Options() = %#v", h)
	}
	if cfg.Feedback.SES == nil || cfg.Feedback.SES.AccountTag != "catraca-account" || cfg.Feedback.UseSend.AccountMetadataKey != "account" {
		t.Errorf("feedback = %#v", cfg.Feedback)
	}
	gh := cfg.SecretScanning.GitHub
	if !gh.Enabled || !gh.Feedback || !gh.Resolver.SendRawToken || gh.KeysURL != "http://127.0.0.1:1/keys" || gh.GitHubToken.Value() != "ghp_x" ||
		gh.MaxAttempts != 50 || gh.MaxAge != 72*time.Hour {
		t.Errorf("github = %#v", gh)
	}
	if cfg.Logging.SlogLevel() != slog.LevelDebug {
		t.Errorf("level = %v", cfg.Logging.SlogLevel())
	}
}

// TestPreviousSecrets checks the secrets being rotated out: read next to
// each secret and handed to the packages after it.
func TestPreviousSecrets(t *testing.T) {
	const old, older = "old_0123456789abcdef0123456789abcdef", "older_0123456789abcdef0123456789abcd"
	cfg := mustParse(t, `
auth:
  tokens:
    - name: platform
      token: `+testToken+`
      previous_tokens: ["${OLD_TOKEN}"]
hooks:
  - name: revoke_key
    url: https://platform.example/hooks/revoke
    secret: `+testSecret+`
    previous_secrets: [`+old+`, `+older+`]
feedback:
  usesend:
    secret: whsec_new
    previous_secrets: [whsec_old]
  generic:
    secret: `+testSecret+`
    previous_secrets: [`+old+`]
secret_scanning:
  github:
    enabled: true
    resolver:
      url: https://platform.example/resolve
      secret: `+testSecret+`
      previous_secrets: [`+old+`]
`, map[string]string{"OLD_TOKEN": testToken + "-old"})
	if got := Values(cfg.Auth.Tokens[0].PreviousTokens); !reflect.DeepEqual(got, []string{testToken + "-old"}) {
		t.Errorf("previous_tokens = %q", got)
	}
	if h := cfg.Hooks[0].Options(); h.Secret != testSecret || !reflect.DeepEqual(h.PreviousSecrets, []string{old, older}) {
		t.Errorf("hooks[0].Options() = %#v, want the secret, then the previous ones in order", h)
	}
	if got := Values(cfg.Feedback.UseSend.PreviousSecrets); !reflect.DeepEqual(got, []string{"whsec_old"}) {
		t.Errorf("usesend previous_secrets = %q", got)
	}
	if got := Values(cfg.Feedback.Generic.PreviousSecrets); !reflect.DeepEqual(got, []string{old}) {
		t.Errorf("generic previous_secrets = %q", got)
	}
	if got := Values(cfg.SecretScanning.GitHub.Resolver.PreviousSecrets); !reflect.DeepEqual(got, []string{old}) {
		t.Errorf("resolver previous_secrets = %q", got)
	}
	// Left out, nothing is being rotated.
	if h := mustParse(t, minimal+"hooks: [{name: a, url: 'https://x', secret: "+testSecret+"}]\n", nil).Hooks[0].Options(); h.PreviousSecrets != nil {
		t.Errorf("previous secrets without any configured: %q", h.PreviousSecrets)
	}

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("config", "config", cfg)
	js, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), string(js), logged.String()} {
		for _, secret := range []string{old, older, "whsec_old", testToken + "-old"} {
			if strings.Contains(out, secret) {
				t.Errorf("a previous secret is printed: %s", out)
			}
		}
	}
}

// TestWatchIntervalZero checks that 0s turns the watch off rather than
// asking for the default.
func TestWatchIntervalZero(t *testing.T) {
	if cfg := mustParse(t, minimal+"rules: {watch_interval: 0s}\n", nil); cfg.Rules.WatchInterval != 0 {
		t.Errorf("watch_interval = %v, want 0", cfg.Rules.WatchInterval)
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
		{"drain", "server: {drain_delay: -1s}", "server.drain_delay: must not be negative, got -1s"},
		{"admin addr", "server: {admin_addr: '9090'}", `server.admin_addr: want host:port, such as :9090 or 127.0.0.1:9090, got "9090"`},
		{"admin addr port", "server: {admin_addr: 'localhost:'}", "server.admin_addr: the port is missing"},
		{"admin addr same", "server: {listen: ':8080', admin_addr: ':8080'}", "server.admin_addr: is the same address as server.listen"},
		{"deadline", "engine: {deadline: -1ms}", "engine.deadline: must be a positive duration, got -1ms"},
		{"max future skew", "engine: {max_future_skew: 0s}", "engine.max_future_skew: must be a positive duration, got 0s"},
		{"max event age", "engine: {max_event_age: -1h}", "engine.max_event_age: must be a positive duration, got -1h0m0s"},
		{"dedupe ttl", "engine: {dedupe_ttl: -1s}", "engine.dedupe_ttl: must be at least 1s, or 0s to turn deduplication off, got -1s"},
		{"short dedupe ttl", "engine: {dedupe_ttl: 500ms}", "engine.dedupe_ttl: must be at least 1s, or 0s to turn deduplication off, got 500ms"},
		{"min labeled", "gate: {min_labeled: 0}", "gate.min_labeled: must be at least 1, got 0"},
		{"min precision", "gate: {min_precision: 1.5}", "gate.min_precision: must be greater than 0 and at most 1, got 1.5"},
		{"store backend", "store: {backend: etcd}", `store.backend: want memory or redis, got "etcd"`},
		{"redis url", "store: {backend: redis}", "store.redis.url: is required with backend: redis"},
		{"redis scheme", "store: {backend: redis, redis: {url: 'http://x'}}", "store.redis.url: want a redis://, rediss:// or unix:// URL"},
		{"redis without backend", "store: {redis: {url: 'redis://x'}}", "store.redis.url: is set but store.backend is memory"},
		{"redis mode without backend", "store: {redis: {mode: cluster}}", "store.redis.mode: is set but store.backend is memory"},
		{"redis mode", "store: {backend: redis, redis: {url: 'redis://x', mode: ring}}", `store.redis.mode: want standalone, sentinel or cluster, got "ring"`},
		{"redis sentinel", "store: {backend: redis, redis: {url: 'redis://x:26379', mode: sentinel}}", "store.redis.url: sentinel mode needs master_name"},
		{"redis cluster scheme", "store: {backend: redis, redis: {url: 'unix:///run/redis.sock', mode: cluster}}", "store.redis.url: invalid URL scheme: unix"},
		{"redis option", "store: {backend: redis, redis: {url: 'redis://x?pool_sise=10'}}", "store.redis.url: unexpected option: pool_sise"},
		{"redis retries", "store: {backend: redis, redis: {url: 'redis://x?max_retries=3'}}", "store.redis.url: max_retries is not supported"},
		{"event detail", "audit: {event_detail: some}", `audit.event_detail: want minimal or full, got "some"`},
		{"sqlite path", "audit: {dsn: 'sqlite:'}", "audit.dsn: the SQLite path is empty"},
		{"retention", "audit: {retention: 0s}", "audit.retention: must be a positive duration"},
		{"short retention", "audit: {retention: 12h}", "audit.retention: must be at least 24h, so decisions stay long enough to be reviewed and labeled; got 12h"},
		{"labeled without retention", "audit: {labeled_retention: 720h}", "audit.labeled_retention: needs audit.retention"},
		{"labeled shorter", "audit: {retention: 720h, labeled_retention: 168h}", "audit.labeled_retention: must be at least audit.retention (720h), got 168h"},
		{"max open conns", "audit: {max_open_conns: 0}", "audit.max_open_conns: must be at least 1, got 0"},
		{"max idle conns", "audit: {max_idle_conns: -1}", "audit.max_idle_conns: must be at least 1, got -1"},
		{"idle above open", "audit: {max_open_conns: 4, max_idle_conns: 8}", "audit.max_idle_conns: must be at most max_open_conns (4), got 8"},
		{"conn lifetime", "audit: {conn_max_lifetime: 0s}", "audit.conn_max_lifetime: must be a positive duration"},
		{"conn idle time", "audit: {conn_max_idle_time: -1s}", "audit.conn_max_idle_time: must be a positive duration"},
		{"hook name", "hooks: [{name: Revoke-Key, url: 'https://x', secret: " + testSecret + "}]", "hooks[0].name: must be lowercase letters"},
		{"hook name required", "hooks: [{url: 'https://x', secret: " + testSecret + "}]", "hooks[0].name: is required"},
		{"hook duplicate", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + "}, {name: a, url: 'https://y', secret: " + testSecret + "}]", "hooks[1].name: another hook already carries out a"},
		{"hook url", "hooks: [{name: a, url: 'ftp://x', secret: " + testSecret + "}]", `hooks[0].url: want an absolute http or https URL, got "ftp://x"`},
		{"hook secret", "hooks: [{name: a, url: 'https://x', secret: short}]", "hooks[0].secret: is 5 characters; use at least 16"},
		{"hook timeout", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", timeout: 0s}]", "hooks[0].timeout: must be a positive duration"},
		{"hook header", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", headers: {Catraca-Signature: x}}]", "hooks[0].headers.Catraca-Signature: Catraca-* headers are set by Catraca"},
		{"hook concurrency", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", concurrency: 0}]", "hooks[0].concurrency: must be at least 1, got 0"},
		{"hook concurrency above workers", "outbox: {workers: 4}\nhooks: [{name: a, url: 'https://x', secret: " + testSecret + ", concurrency: 5}]", "hooks[0].concurrency: must be at most outbox.workers (4), got 5"},
		{"hook max attempts", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", max_attempts: -1}]", "hooks[0].max_attempts: must be at least 1, got -1"},
		{"hook max age", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", max_age: 0s}]", "hooks[0].max_age: must be a positive duration"},
		{"hook max age under timeout", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", timeout: 30s, max_age: 30s}]", "hooks[0].max_age: must be longer than the hook's timeout (30s), got 30s"},
		{"outbox workers", "outbox: {workers: 0}", "outbox.workers: must be at least 1, got 0"},
		{"dispatch timeout", "engine: {dispatch_timeout: 0s}", "engine.dispatch_timeout: must be a positive duration, got 0s"},
		{"ses topics", "feedback: {ses: {account_tag: t}}", "feedback.ses.topic_arns: at least one SNS topic ARN is required"},
		{"ses arn", "feedback: {ses: {topic_arns: [catraca], account_tag: t}}", `feedback.ses.topic_arns[0]: want an SNS topic ARN`},
		{"ses account", "feedback: {ses: {topic_arns: ['arn:aws:sns:us-east-1:1:t']}}", "feedback.ses: set account_tag, account_header or both"},
		{"usesend secret", "feedback: {usesend: {}}", "feedback.usesend.secret: is required"},
		{"generic secret", "feedback:\n  generic:\n", "feedback.generic.secret: is required"},
		{"github resolver", "secret_scanning: {github: {enabled: true}}", "secret_scanning.github.resolver.url: is required"},
		{"github resolver secret", "secret_scanning: {github: {enabled: true, resolver: {url: 'https://r'}}}", "secret_scanning.github.resolver.secret: is required"},
		{"github raw token", "secret_scanning: {github: {enabled: true, resolver: {url: 'http://r', secret: " + testSecret + ", send_raw_token: true}}}", "secret_scanning.github.resolver.send_raw_token: sends live credentials, so the resolver URL must be https"},
		{"github keys url", "secret_scanning: {github: {enabled: true, resolver: {url: 'https://r', secret: " + testSecret + "}, keys_url: nope}}", "secret_scanning.github.keys_url: want an absolute http or https URL"},
		{"github max attempts", "secret_scanning: {github: {max_attempts: 0}}", "secret_scanning.github.max_attempts: must be at least 1, got 0"},
		{"github max age", "secret_scanning: {github: {max_age: 0s}}", "secret_scanning.github.max_age: must be a positive duration"},
		{"log level", "logging: {level: loud}", `logging.level: want debug, info, warn or error, got "loud"`},
		{"log format", "logging: {format: xml}", `logging.format: want json or text, got "xml"`},
		{"watch interval", "rules: {watch_interval: -1s}", "rules.watch_interval: must be at least 1s, or 0s to turn the watch off, got -1s"},
		{"short watch interval", "rules: {watch_interval: 100ms}", "rules.watch_interval: must be at least 1s, or 0s to turn the watch off, got 100ms"},
		{"gate on load", "gate: {on_load: block}", `gate.on_load: want off, warn or enforce, got "block"`},
		{"hook previous empty", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", previous_secrets: ['']}]", "hooks[0].previous_secrets[0]: is empty; remove it from the list once the rotation is over"},
		{"hook previous short", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", previous_secrets: [short]}]", "hooks[0].previous_secrets[0]: is 5 characters; use at least 16"},
		{"hook previous current", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", previous_secrets: [" + testSecret + "]}]", "hooks[0].previous_secrets[0]: is the current secret; list only the secrets being rotated out"},
		{"hook previous twice", "hooks: [{name: a, url: 'https://x', secret: " + testSecret + ", previous_secrets: [" + testToken + ", " + testToken + "]}]", "hooks[0].previous_secrets[1]: is listed twice"},
		{"generic previous", "feedback: {generic: {secret: " + testSecret + ", previous_secrets: ['']}}", "feedback.generic.previous_secrets[0]: is empty"},
		{"usesend previous", "feedback: {usesend: {secret: whsec_a, previous_secrets: [whsec_a]}}", "feedback.usesend.previous_secrets[0]: is the current secret"},
		{"usesend previous space", "feedback: {usesend: {secret: whsec_a, previous_secrets: [' whsec_b']}}", "feedback.usesend.previous_secrets[0]: has leading or trailing whitespace"},
		{"resolver previous", "secret_scanning: {github: {enabled: true, resolver: {url: 'https://r', secret: " + testSecret + ", previous_secrets: [x]}}}", "secret_scanning.github.resolver.previous_secrets[0]: is 1 characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireError(t, parseErrors(t, minimal+tt.yaml+"\n", nil), tt.want)
		})
	}
}

// TestDerivedDefaults checks the defaults taken from other fields: the
// dispatch budget from the deadline, and a hook's concurrency from a pool
// of workers smaller than its default.
func TestDerivedDefaults(t *testing.T) {
	cfg := mustParse(t, minimal+`engine: {deadline: 25ms}
outbox: {workers: 2}
hooks: [{name: a, url: 'https://x', secret: `+testSecret+`}]
`, nil)
	if cfg.Engine.DispatchTimeout != 25*time.Millisecond {
		t.Errorf("dispatch_timeout = %v, want the deadline, 25ms", cfg.Engine.DispatchTimeout)
	}
	if cfg.Hooks[0].Concurrency != 2 {
		t.Errorf("hooks[0].concurrency = %d, want the 2 workers", cfg.Hooks[0].Concurrency)
	}
}

// TestDrainDelayZero checks that 0s, unlike for other durations, is a
// setting: it turns the drain off.
func TestDrainDelayZero(t *testing.T) {
	cfg := mustParse(t, minimal+"server: {drain_delay: 0s}\n", nil)
	if cfg.Server.DrainDelay != 0 {
		t.Errorf("drain_delay = %v, want 0", cfg.Server.DrainDelay)
	}
	cfg = mustParse(t, minimal+"server: {drain_delay: 15s}\n", nil)
	if cfg.Server.DrainDelay != 15*time.Second {
		t.Errorf("drain_delay = %v, want 15s", cfg.Server.DrainDelay)
	}
}

// TestDedupeTTLZero checks that 0s turns deduplication off rather than
// asking for the default.
func TestDedupeTTLZero(t *testing.T) {
	cfg := mustParse(t, minimal+"engine: {dedupe_ttl: 0s}\n", nil)
	if cfg.Engine.DedupeTTL != 0 {
		t.Errorf("dedupe_ttl = %v, want 0", cfg.Engine.DedupeTTL)
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

	// A previous token names its client like the current one, so it may
	// not be any other token of the list.
	msgs = parseErrors(t, `auth:
  tokens:
    - name: platform
      token: `+testToken+`
      previous_tokens: ["", short, `+testToken+`, `+testSecret+`]
    - name: ops
      token: `+testSecret+`
      previous_tokens: [`+testToken+`-old, `+testToken+`-old]
`, nil)
	for _, want := range []string{
		"auth.tokens[0].previous_tokens[0]: is empty; remove it from the list once the client uses the new token",
		"auth.tokens[0].previous_tokens[1]: is 5 characters",
		"auth.tokens[0].previous_tokens[2]: is the current token",
		"auth.tokens[1].token: the same token is configured twice",
		"auth.tokens[1].previous_tokens[1]: the same token is configured twice",
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
