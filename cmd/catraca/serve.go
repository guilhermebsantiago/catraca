package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"runtime"
	"runtime/debug"
	"strings"
	"text/tabwriter"

	"github.com/guilhermebsantiago/catraca/internal/app"
	"github.com/guilhermebsantiago/catraca/internal/config"
	"github.com/guilhermebsantiago/catraca/internal/decision"
	"github.com/guilhermebsantiago/catraca/internal/rules"
)

// configFlag adds -config, which defaults to $CATRACA_CONFIG or catraca.yaml.
func (c *cli) configFlag(fs *flag.FlagSet) *string {
	def := c.getenv("CATRACA_CONFIG")
	if def == "" {
		def = "catraca.yaml"
	}
	return fs.String("config", def, "the configuration file (default $CATRACA_CONFIG, else catraca.yaml)")
}

// loadConfig loads the configuration, printing every problem in it.
func (c *cli) loadConfig(path string) (*config.Config, int) {
	cfg, err := config.LoadWith(path, c.lookupEnv)
	if err == nil {
		return cfg, -1
	}
	var list config.ErrorList
	if errors.As(err, &list) {
		for _, e := range list {
			fmt.Fprintln(c.stderr, e)
		}
		c.errorf("%s: %d problem(s)", path, len(list))
		return nil, exitFailed
	}
	c.errorf("%v", err)
	return nil, exitError
}

func (c *cli) serve(ctx context.Context, args []string) int {
	fs := c.flagSet("serve", `Usage: catraca serve [-config catraca.yaml]

Runs the server until it receives SIGINT or SIGTERM, then shuts down
gracefully. On Unix, SIGHUP reloads the ruleset. Logs go to stderr.
`)
	path := c.configFlag(fs)
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	cfg, code := c.loadConfig(*path)
	if cfg == nil {
		return code
	}
	log := app.NewLogger(cfg.Logging, c.stderr)
	a, err := app.New(ctx, cfg, app.Options{Logger: log, Version: version})
	if err != nil {
		log.Error("catraca could not start", "error", err)
		return exitError
	}
	if err := a.Run(ctx); err != nil {
		log.Error("catraca stopped with an error", "error", err)
		return exitError
	}
	return exitOK
}

func (c *cli) configCheck(_ context.Context, args []string) int {
	fs := c.flagSet("config check", `Usage: catraca config check [-config catraca.yaml]

Validates the configuration and the ruleset it names without starting the
server, and prints a summary. Problems are errors; ruleset lint findings and
effects without a hook are warnings.
`)
	path := c.configFlag(fs)
	if _, code := parse(fs, args, 0, 0); code >= 0 {
		return code
	}
	cfg, code := c.loadConfig(*path)
	if cfg == nil {
		return code
	}
	rs, err := rules.LoadFile(cfg.Rules.Path)
	if err != nil {
		c.printRulesError(cfg.Rules.Path, err)
		c.errorf("%s: rules.path: the ruleset does not load", *path)
		return exitFailed
	}
	warnings := 0
	for _, w := range rs.Lint() {
		fmt.Fprintln(c.stderr, formatWarning(cfg.Rules.Path, w))
		warnings++
	}
	for _, m := range app.MissingHooks(rs, cfg.Hooks) {
		fmt.Fprintf(c.stderr, "%s: warning: %s\n", cfg.Rules.Path, m)
		warnings++
	}
	fmt.Fprintf(c.stdout, "%s is valid", *path)
	if warnings > 0 {
		fmt.Fprintf(c.stdout, " (%d warning(s))", warnings)
	}
	fmt.Fprintln(c.stdout)
	c.summary(cfg, rs)
	return exitOK
}

// summary prints what the configuration sets up, without secrets.
func (c *cli) summary(cfg *config.Config, rs *rules.Ruleset) {
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	row := func(k, format string, args ...any) {
		fmt.Fprintf(tw, "  %s\t"+format+"\n", append([]any{k}, args...)...)
	}

	row("listen", "%s", cfg.Server.Listen)
	var names []string
	for _, t := range cfg.Auth.Tokens {
		names = append(names, t.Name)
	}
	row("api tokens", "%s", strings.Join(names, ", "))
	enforced := 0
	for _, r := range rs.Rules() {
		if r.Mode == decision.Enforce {
			enforced++
		}
	}
	row("ruleset", "%s (version %s, %d rules: %d enforced, %d shadow)", cfg.Rules.Path, rs.Version(), len(rs.Rules()), enforced, len(rs.Rules())-enforced)
	if cfg.Store.Backend == config.StoreRedis {
		row("store", "redis at %s, prefix %q", hostOf(cfg.Store.Redis.URL.Value()), cfg.Store.Redis.Prefix)
	} else {
		row("store", "memory (one instance; counters are lost on restart)")
	}
	dsn := cfg.Audit.DSN.Value()
	if !cfg.Audit.IsSQLite() {
		if u, err := url.Parse(dsn); err == nil {
			dsn = u.Redacted()
		}
	}
	row("audit", "%s, %s events", dsn, cfg.Audit.EventDetail)
	row("deadline", "%s", cfg.Engine.Deadline)
	row("event time", "at most %s ahead of the clock (later is clamped), %s behind (older is rejected)", cfg.Engine.MaxFutureSkew, cfg.Engine.MaxEventAge)
	row("gate", "%d labeled matches, precision lower bound %.2f", cfg.Gate.MinLabeled, cfg.Gate.MinPrecision)
	names = nil
	for _, h := range cfg.Hooks {
		names = append(names, fmt.Sprintf("%s -> %s", h.Name, hostOf(h.URL)))
	}
	row("hooks", "%s", orNone(names))
	names = nil
	if cfg.Feedback.SES != nil {
		names = append(names, "ses")
	}
	if cfg.Feedback.UseSend != nil {
		names = append(names, "usesend")
	}
	if cfg.Feedback.Generic != nil {
		names = append(names, "generic")
	}
	row("feedback", "%s", orNone(names))
	if gh := cfg.SecretScanning.GitHub; gh.Enabled {
		row("github", "enabled, resolver %s, feedback %t", hostOf(gh.Resolver.URL), gh.Feedback)
	} else {
		row("github", "disabled")
	}
	row("logging", "%s, %s", cfg.Logging.Level, cfg.Logging.Format)
	_ = tw.Flush()
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	return u.Host
}

func orNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func (c *cli) version() int {
	fmt.Fprintf(c.stdout, "catraca %s", version)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				fmt.Fprintf(c.stdout, " (%s)", s.Value[:12])
			}
		}
	}
	fmt.Fprintf(c.stdout, " %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return exitOK
}
