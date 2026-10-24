package app

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/guilhermebsantiago/catraca/internal/config"
)

// fullApp builds a server with every part that registers metrics turned on:
// hooks, the three feedback providers and secret scanning. Nothing calls
// out: no hook has a delivery, and GitHub's keys are fetched only for a
// batch.
func fullApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte("version: 1\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const secret = "metrics-test-secret-0123456789abcdef"
	yaml := fmt.Sprintf(`
auth:
  tokens: [{name: test, token: %[1]s}]
rules: {path: '%[2]s'}
audit: {dsn: 'sqlite:%[3]s'}
hooks:
  - {name: revoke_key, url: 'http://127.0.0.1:1/revoke', secret: %[1]s}
feedback:
  ses: {topic_arns: ['arn:aws:sns:us-east-1:111122223333:catraca'], account_tag: account}
  usesend: {secret: %[1]s}
  generic: {secret: %[1]s}
secret_scanning:
  github:
    enabled: true
    keys_url: http://127.0.0.1:1/keys
    resolver: {url: 'http://127.0.0.1:1/resolve', secret: %[1]s}
`, secret, filepath.ToSlash(rules), filepath.ToSlash(filepath.Join(dir, "audit.db")))
	cfg, err := config.Parse([]byte(yaml), "", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), cfg, Options{Logger: slog.New(slog.DiscardHandler), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return a
}

var fqName = regexp.MustCompile(`fqName: "([^"]+)"`)

// registeredMetrics returns the names of the catraca_* metrics a registers,
// whether or not they have a series yet: a rule's matches have none until it
// matches.
func registeredMetrics(t *testing.T, a *App) map[string]bool {
	t.Helper()
	ch := make(chan *prometheus.Desc)
	go func() {
		a.registry.Describe(ch)
		close(ch)
	}()
	names := map[string]bool{}
	for d := range ch {
		m := fqName.FindStringSubmatch(d.String())
		if m == nil {
			t.Fatalf("no name in %s", d)
		}
		if strings.HasPrefix(m[1], "catraca_") {
			names[m[1]] = true
		}
	}
	return names
}

// documentedMetrics reads the metrics table of docs/api.md (GET /metrics):
// the names in the first column, where `_dropped_total` after
// `catraca_audit_recorded_total` stands for catraca_audit_dropped_total.
func documentedMetrics(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "docs", "api.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names := map[string]bool{}
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "### GET /metrics":
			in = true
			continue
		case in && strings.HasPrefix(line, "#"):
			in = false
		}
		if !in || !strings.HasPrefix(line, "| `") {
			continue
		}
		cell := strings.Split(line, "|")[1]
		prefix := ""
		for i, name := range strings.Split(cell, "`") {
			if i%2 == 0 || strings.Contains(name, "*") {
				continue // outside backticks, or go_sql_*
			}
			name, _, _ = strings.Cut(name, "{")
			if strings.HasPrefix(name, "_") {
				name = prefix + name
			} else if parts := strings.SplitN(name, "_", 3); len(parts) == 3 {
				prefix = parts[0] + "_" + parts[1]
			}
			names[name] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("no metrics table under ### GET /metrics in docs/api.md")
	}
	return names
}

// TestMetricsAreDocumented keeps docs/api.md's table of metrics and the
// metrics the server registers the same, both ways.
func TestMetricsAreDocumented(t *testing.T) {
	registered := registeredMetrics(t, fullApp(t))
	documented := documentedMetrics(t)
	for _, name := range sortedKeys(registered) {
		if !documented[name] {
			t.Errorf("%s is registered but not in the metrics table of docs/api.md", name)
		}
	}
	for _, name := range sortedKeys(documented) {
		if !registered[name] {
			t.Errorf("%s is in the metrics table of docs/api.md but not registered", name)
		}
	}
}

// metricName finds metric names in prose, queries and dashboards. A
// histogram's series end in _bucket, _count and _sum.
var metricName = regexp.MustCompile(`\bcatraca_[a-z_]+[a-z]`)

// TestMetricsNamedElsewhereExist checks that every catraca_* metric the
// other documents, the alerting rules and the dashboard name is one the
// server registers, so a renamed metric cannot leave an alert that never
// fires.
func TestMetricsNamedElsewhereExist(t *testing.T) {
	registered := registeredMetrics(t, fullApp(t))
	var files []string
	for _, pattern := range []string{"docs/*.md", "README.md", "deploy/prometheus/*.yaml", "deploy/grafana/*.json"} {
		matches, err := filepath.Glob(filepath.Join("..", "..", filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, loc := range metricName.FindAllStringIndex(string(data), -1) {
			name := string(data[loc[0]:loc[1]])
			// A database in a DSN, such as .../catraca_test, is no metric.
			if loc[0] > 0 && data[loc[0]-1] == '/' {
				continue
			}
			base := name
			for _, suffix := range []string{"_bucket", "_count", "_sum"} {
				if b, ok := strings.CutSuffix(name, suffix); ok && registered[b] {
					base = b
				}
			}
			if !registered[base] && !seen[name] {
				seen[name] = true
				t.Errorf("%s names %s, which the server does not register", filepath.ToSlash(file), name)
			}
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
