package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/audit"
	"github.com/guilhermebsantiago/catraca/internal/store"
)

// minSecretLen is the shortest API token or shared secret accepted. Catraca
// compares them in constant time, but a short one can still be guessed.
const minSecretLen = 16

var (
	// effectName matches the effect names rules may list, which name hooks.
	effectName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	tokenName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// validator checks a decoded configuration and adds its findings to the
// decoder's errors, at the line of the field they are about.
type validator struct {
	d *decoder
}

func (v *validator) add(path, format string, args ...any) {
	if v.failed(path) {
		return
	}
	v.d.errs = append(v.d.errs, &Error{File: v.d.file, Line: v.line(path), Path: path, Msg: fmt.Sprintf(format, args...)})
}

// isSet reports whether the field is written in the file.
func (v *validator) isSet(path string) bool {
	_, ok := v.d.lines[path]
	return ok
}

// line returns the line of the field, or of its closest parent in the file.
func (v *validator) line(path string) int {
	for p := path; p != ""; p = parent(p) {
		if l, ok := v.d.lines[p]; ok {
			return l
		}
	}
	return 0
}

// failed reports whether the field or a parent failed to decode.
func (v *validator) failed(path string) bool {
	for p := path; p != ""; p = parent(p) {
		if v.d.bad[p] {
			return true
		}
	}
	return false
}

// parent returns the path of the field that contains path: "a.b[0].c" ->
// "a.b[0]" -> "a.b" -> "a" -> "".
func parent(path string) string {
	i := strings.LastIndexAny(path, ".[")
	if i < 0 {
		return ""
	}
	return path[:i]
}

// explicit checks the numbers that take a default when left out, before the
// defaults are applied: writing 0 for them is a mistake, not a request for
// the default.
func (v *validator) explicit(c *Config) {
	if v.isSet("server.max_body_bytes") && c.Server.MaxBodyBytes < 1024 {
		v.add("server.max_body_bytes", "must be at least 1024 bytes, got %d", c.Server.MaxBodyBytes)
	}
	v.positive("server.shutdown_timeout", c.Server.ShutdownTimeout)
	if c.Server.DrainDelay < 0 {
		// 0s is allowed: it turns the drain off.
		v.add("server.drain_delay", "must not be negative, got %s; 0s turns the drain off", c.Server.DrainDelay)
	}
	if v.isSet("server.max_inflight") && c.Server.MaxInflight < 1 {
		v.add("server.max_inflight", "must be at least 1, got %d", c.Server.MaxInflight)
	}
	if c.Server.InflightWait < 0 {
		// 0s is allowed: a request over the limit is shed at once.
		v.add("server.inflight_wait", "must not be negative, got %s; 0s sheds at once", c.Server.InflightWait)
	}
	v.positive("engine.deadline", c.Engine.Deadline)
	v.positive("engine.dispatch_timeout", c.Engine.DispatchTimeout)
	v.positive("engine.max_future_skew", c.Engine.MaxFutureSkew)
	v.positive("engine.max_event_age", c.Engine.MaxEventAge)
	if d := c.Engine.DedupeTTL; d < 0 || (d > 0 && d < time.Second) {
		// 0s is allowed: it turns deduplication off. Below a second it
		// would outlast no retry.
		v.add("engine.dedupe_ttl", "must be at least 1s, or 0s to turn deduplication off, got %s", d)
	}
	if d := c.Engine.RecipientMemory; d < 0 || (d > 0 && d < time.Hour) {
		v.add("engine.recipient_memory", "must be at least 1h, or 0s to turn the recipient memory off, got %s", d)
	}
	if v.isSet("engine.breaker.failure_threshold") && c.Engine.Breaker.FailureThreshold < 1 {
		v.add("engine.breaker.failure_threshold", "must be at least 1, got %d", c.Engine.Breaker.FailureThreshold)
	}
	v.positive("engine.breaker.failure_window", c.Engine.Breaker.FailureWindow)
	v.positive("engine.breaker.cooldown", c.Engine.Breaker.Cooldown)
	if v.isSet("engine.breaker.probes") && c.Engine.Breaker.Probes < 1 {
		v.add("engine.breaker.probes", "must be at least 1, got %d", c.Engine.Breaker.Probes)
	}
	if d := c.Rules.WatchInterval; d < 0 || (d > 0 && d < time.Second) {
		// 0s is allowed: it turns the watch off. Below a second, reading
		// the file costs more than it is worth.
		v.add("rules.watch_interval", "must be at least 1s, or 0s to turn the watch off, got %s", d)
	}
	if v.isSet("gate.min_labeled") && c.Gate.MinLabeled < 1 {
		v.add("gate.min_labeled", "must be at least 1, got %d", c.Gate.MinLabeled)
	}
	if v.isSet("gate.min_precision") && (c.Gate.MinPrecision <= 0 || c.Gate.MinPrecision > 1) {
		v.add("gate.min_precision", "must be greater than 0 and at most 1, got %g", c.Gate.MinPrecision)
	}
	for i, h := range c.Hooks {
		path := fmt.Sprintf("hooks[%d]", i)
		v.positive(path+".timeout", h.Timeout)
		v.atLeastOne(path+".concurrency", h.Concurrency)
		v.atLeastOne(path+".max_attempts", h.MaxAttempts)
		v.positive(path+".max_age", h.MaxAge)
	}
	v.atLeastOne("outbox.workers", c.Outbox.Workers)
	if v.isSet("audit.max_open_conns") && c.Audit.MaxOpenConns < 1 {
		v.add("audit.max_open_conns", "must be at least 1, got %d", c.Audit.MaxOpenConns)
	}
	if v.isSet("audit.max_idle_conns") && c.Audit.MaxIdleConns < 1 {
		v.add("audit.max_idle_conns", "must be at least 1, got %d", c.Audit.MaxIdleConns)
	}
	v.positive("audit.conn_max_lifetime", c.Audit.ConnMaxLifetime)
	v.positive("audit.conn_max_idle_time", c.Audit.ConnMaxIdleTime)
	v.positive("audit.retention", c.Audit.Retention)
	v.positive("audit.labeled_retention", c.Audit.LabeledRetention)
	if v.isSet("secret_scanning.github.max_attempts") && c.SecretScanning.GitHub.MaxAttempts < 1 {
		v.add("secret_scanning.github.max_attempts", "must be at least 1, got %d", c.SecretScanning.GitHub.MaxAttempts)
	}
	v.positive("secret_scanning.github.max_age", c.SecretScanning.GitHub.MaxAge)
}

func (v *validator) positive(path string, d time.Duration) {
	if v.isSet(path) && d <= 0 {
		v.add(path, "must be a positive duration, got %s", d)
	}
}

func (v *validator) atLeastOne(path string, n int) {
	if v.isSet(path) && n < 1 {
		v.add(path, "must be at least 1, got %d", n)
	}
}

// durationText prints a duration the way it is written in the file: 720h,
// not 720h0m0s.
func durationText(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func (v *validator) config(c *Config) {
	v.server(c.Server)
	v.auth(c.Auth)
	if strings.TrimSpace(c.Rules.Path) == "" {
		v.add("rules.path", "is required")
	}
	switch c.Gate.OnLoad {
	case GateOff, GateWarn, GateEnforce:
	default:
		v.add("gate.on_load", "want off, warn or enforce, got %q", c.Gate.OnLoad)
	}
	v.store(c.Store)
	v.audit(c.Audit)
	v.hooks(c.Hooks, c.Outbox)
	v.feedback(c.Feedback)
	v.github(c.SecretScanning.GitHub)
	v.logging(c.Logging)
	v.tracing(c.Tracing)
}

func (v *validator) server(s Server) {
	v.address("server.listen", s.Listen, ":8080 or 127.0.0.1:8080")
	if s.InflightLimit != InflightAdaptive && s.InflightLimit != InflightStatic {
		v.add("server.inflight_limit", "want adaptive or static, got %q", s.InflightLimit)
	}
	if s.AdminAddr == "" {
		return
	}
	if v.address("server.admin_addr", s.AdminAddr, ":9090 or 127.0.0.1:9090") && s.AdminAddr == s.Listen {
		v.add("server.admin_addr", "is the same address as server.listen; use another port, or leave admin_addr out to serve health and metrics on listen")
	}
}

// address checks a host:port to listen on and reports whether it is valid.
func (v *validator) address(path, addr, example string) bool {
	host, port, err := net.SplitHostPort(addr)
	switch {
	case err != nil:
		v.add(path, "want host:port, such as %s, got %q", example, addr)
	case port == "":
		v.add(path, "the port is missing in %q", addr)
	case strings.ContainsAny(host, "/ "):
		v.add(path, "invalid host %q", host)
	default:
		return true
	}
	return false
}

func (v *validator) auth(a Auth) {
	if len(a.Tokens) == 0 {
		v.add("auth.tokens", "at least one API token is required: every /v1 route except feedback and secret scanning needs one")
		return
	}
	names, values := map[string]bool{}, map[Secret]bool{}
	for i, t := range a.Tokens {
		path := fmt.Sprintf("auth.tokens[%d]", i)
		switch {
		case t.Name == "":
			v.add(path+".name", "is required: it identifies the token in access logs")
		case !tokenName.MatchString(t.Name):
			v.add(path+".name", "must be letters, digits, '.', '_' and '-', got %q", t.Name)
		case names[t.Name]:
			v.add(path+".name", "%q is used by another token", t.Name)
		}
		names[t.Name] = true
		// A token, current or previous, names one client, so it may appear
		// once in the whole list.
		if v.secret(path+".token", t.Token) {
			if values[t.Token] {
				v.add(path+".token", "the same token is configured twice")
			}
			values[t.Token] = true
		}
		for j, p := range t.PreviousTokens {
			pp := fmt.Sprintf("%s.previous_tokens[%d]", path, j)
			switch {
			case p == "":
				v.add(pp, "is empty; remove it from the list once the client uses the new token")
			case !v.secret(pp, p):
			case p == t.Token:
				v.add(pp, "is the current token; list only the tokens being rotated out")
			case values[p]:
				v.add(pp, "the same token is configured twice")
			}
			values[p] = true
		}
		v.scopes(path+".scopes", t.Scopes)
	}
}

// scopes checks the scopes of a token. Leaving the key out gives every
// scope; an empty list would give none, which is a mistake rather than a
// way to turn a token off.
func (v *validator) scopes(path string, scopes []string) {
	if v.isSet(path) && len(scopes) == 0 {
		v.add(path, "is empty: list at least one of %s, or remove the key for every scope", strings.Join(TokenScopes, ", "))
		return
	}
	seen := map[string]bool{}
	for i, sc := range scopes {
		p := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case !slices.Contains(TokenScopes, sc):
			v.add(p, "unknown scope %q: use %s", sc, strings.Join(TokenScopes, ", "))
		case seen[sc]:
			v.add(p, "%q is listed twice", sc)
		}
		seen[sc] = true
	}
}

// previous checks the secrets being rotated out next to current: each must
// be acceptable to check, and none may repeat current or another one, which
// would mean nothing is being rotated. An empty one is a mistake rather
// than a way to turn the list off: an HMAC keyed with it can be forged.
func (v *validator) previous(path string, current Secret, previous []Secret, check func(path string, s Secret) bool) {
	seen := map[Secret]bool{}
	for i, s := range previous {
		p := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case s == "":
			v.add(p, "is empty; remove it from the list once the rotation is over")
		case !check(p, s):
		case s == current:
			v.add(p, "is the current secret; list only the secrets being rotated out")
		case seen[s]:
			v.add(p, "is listed twice")
		}
		seen[s] = true
	}
}

// trimmed checks that a secret has no leading or trailing whitespace, a
// sign of a copy and paste that went wrong.
func (v *validator) trimmed(path string, s Secret) bool {
	if strings.TrimSpace(s.Value()) != s.Value() {
		v.add(path, "has leading or trailing whitespace")
		return false
	}
	return true
}

// secret checks a shared secret and reports whether it is acceptable.
func (v *validator) secret(path string, s Secret) bool {
	switch {
	case s == "":
		v.add(path, "is required")
	case len(s) < minSecretLen:
		v.add(path, "is %d characters; use at least %d random characters (for example: openssl rand -hex 32)", len(s), minSecretLen)
	case strings.TrimSpace(s.Value()) != s.Value():
		v.add(path, "has leading or trailing whitespace")
	default:
		return true
	}
	return false
}

func (v *validator) store(s Store) {
	switch s.Backend {
	case StoreMemory:
		if s.Redis.URL != "" {
			v.add("store.redis.url", "is set but store.backend is memory; set backend: redis to use Redis")
		}
		if v.isSet("store.redis.mode") {
			v.add("store.redis.mode", "is set but store.backend is memory; set backend: redis to use Redis")
		}
	case StoreRedis:
		switch s.Redis.Mode {
		case store.RedisStandalone, store.RedisSentinel, store.RedisCluster:
		default:
			v.add("store.redis.mode", "want standalone, sentinel or cluster, got %q", s.Redis.Mode)
			return
		}
		if s.Redis.URL == "" {
			v.add("store.redis.url", "is required with backend: redis")
			return
		}
		u, err := url.Parse(s.Redis.URL.Value())
		if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss" && u.Scheme != "unix") {
			v.add("store.redis.url", "want a redis://, rediss:// or unix:// URL")
			return
		}
		// The rest of what the server would refuse at start: unknown
		// parameters, a sentinel URL without master_name, max_retries. The
		// message never repeats the URL.
		if err := store.CheckRedisURL(s.Redis.URL.Value(), s.Redis.Mode); err != nil {
			msg := strings.TrimPrefix(err.Error(), "store: redis url: ")
			v.add("store.redis.url", "%s", strings.TrimPrefix(msg, "redis: "))
		}
	default:
		v.add("store.backend", "want memory or redis, got %q", s.Backend)
	}
}

func (v *validator) audit(a Audit) {
	if _, err := audit.ParseEventMode(a.EventDetail); err != nil {
		v.add("audit.event_detail", "want minimal or full, got %q", a.EventDetail)
	}
	if a.MaxOpenConns >= 1 && a.MaxIdleConns > a.MaxOpenConns {
		v.add("audit.max_idle_conns", "must be at most max_open_conns (%d), got %d", a.MaxOpenConns, a.MaxIdleConns)
	}
	switch {
	case a.Retention > 0 && a.Retention < audit.MinRetention:
		v.add("audit.retention", "must be at least %s, so decisions stay long enough to be reviewed and labeled; got %s",
			durationText(audit.MinRetention), durationText(a.Retention))
	case a.LabeledRetention > 0 && a.Retention == 0:
		v.add("audit.labeled_retention", "needs audit.retention: unlabeled decisions cannot be kept longer than labeled ones")
	case a.LabeledRetention > 0 && a.LabeledRetention < a.Retention:
		v.add("audit.labeled_retention", "must be at least audit.retention (%s), got %s: labeled decisions are the ones worth keeping",
			durationText(a.Retention), durationText(a.LabeledRetention))
	}
	if !a.IsSQLite() {
		if _, err := url.Parse(a.DSN.Value()); err != nil {
			v.add("audit.dsn", "is not a valid postgres:// URL")
		}
		return
	}
	if strings.TrimSpace(a.SQLitePath()) == "" {
		v.add("audit.dsn", "the SQLite path is empty")
	}
}

func (v *validator) hooks(hooks []Hook, o Outbox) {
	seen := map[string]bool{}
	for i, h := range hooks {
		path := fmt.Sprintf("hooks[%d]", i)
		switch {
		case h.Name == "":
			v.add(path+".name", "is required: the effect the hook carries out, as rules list it")
		case !effectName.MatchString(h.Name):
			v.add(path+".name", "must be lowercase letters, digits and underscores, starting with a letter, like the effects rules list; got %q", h.Name)
		case seen[h.Name]:
			v.add(path+".name", "another hook already carries out %s", h.Name)
		}
		seen[h.Name] = true
		v.httpURL(path+".url", h.URL, true)
		v.secret(path+".secret", h.Secret)
		v.previous(path+".previous_secrets", h.Secret, h.PreviousSecrets, v.secret)
		if o.Workers >= 1 && h.Concurrency > o.Workers {
			v.add(path+".concurrency", "must be at most outbox.workers (%d), got %d: deliveries of every hook share those workers",
				o.Workers, h.Concurrency)
		}
		if h.MaxAge > 0 && h.Timeout > 0 && h.MaxAge <= h.Timeout {
			v.add(path+".max_age", "must be longer than the hook's timeout (%s), got %s: it bounds every attempt of a delivery together",
				durationText(h.Timeout), durationText(h.MaxAge))
		}
		for name := range h.Headers {
			hp := path + ".headers." + name
			switch {
			case !headerName.MatchString(name):
				v.add(hp, "is not a valid header name")
			case strings.HasPrefix(strings.ToLower(name), "catraca-"):
				v.add(hp, "Catraca-* headers are set by Catraca and cannot be replaced")
			}
		}
	}
}

// httpURL checks an absolute http or https URL.
func (v *validator) httpURL(path, raw string, required bool) bool {
	if raw == "" {
		if required {
			v.add(path, "is required")
		}
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		v.add(path, "want an absolute http or https URL, got %q", raw)
		return false
	}
	return true
}

func (v *validator) feedback(f Feedback) {
	if s := f.SES; s != nil {
		if len(s.TopicARNs) == 0 {
			v.add("feedback.ses.topic_arns", "at least one SNS topic ARN is required")
		}
		for i, arn := range s.TopicARNs {
			if parts := strings.Split(arn, ":"); len(parts) < 6 || parts[0] != "arn" || parts[2] != "sns" {
				v.add(fmt.Sprintf("feedback.ses.topic_arns[%d]", i), "want an SNS topic ARN such as arn:aws:sns:us-east-1:111122223333:catraca, got %q", arn)
			}
		}
		if s.AccountTag == "" && s.AccountHeader == "" {
			v.add("feedback.ses", "set account_tag, account_header or both: the account id of each notification is read from them")
		}
	}
	if u := f.UseSend; u != nil {
		if u.Secret == "" {
			v.add("feedback.usesend.secret", "is required: the webhook signing secret shown by useSend")
		}
		// useSend makes its secrets, so their length is not checked here.
		v.previous("feedback.usesend.previous_secrets", u.Secret, u.PreviousSecrets, v.trimmed)
	}
	if g := f.Generic; g != nil {
		v.secret("feedback.generic.secret", g.Secret)
		v.previous("feedback.generic.previous_secrets", g.Secret, g.PreviousSecrets, v.secret)
	}
}

func (v *validator) github(g GitHub) {
	if !g.Enabled {
		return
	}
	const p = "secret_scanning.github"
	if v.httpURL(p+".resolver.url", g.Resolver.URL, true) && g.Resolver.SendRawToken {
		if u, _ := url.Parse(g.Resolver.URL); u.Scheme != "https" {
			v.add(p+".resolver.send_raw_token", "sends live credentials, so the resolver URL must be https")
		}
	}
	v.secret(p+".resolver.secret", g.Resolver.Secret)
	v.previous(p+".resolver.previous_secrets", g.Resolver.Secret, g.Resolver.PreviousSecrets, v.secret)
	v.httpURL(p+".keys_url", g.KeysURL, false)
}

func (v *validator) logging(l Logging) {
	switch strings.ToLower(l.Level) {
	case "debug", "info", "warn", "error":
	default:
		v.add("logging.level", "want debug, info, warn or error, got %q", l.Level)
	}
	switch l.Format {
	case "json", "text":
	default:
		v.add("logging.format", "want json or text, got %q", l.Format)
	}
}
