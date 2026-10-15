// Command catraca runs the Catraca server and the tools around its rules:
// checking and testing rulesets, the precision gate, backtests, precision
// reports and labeling decisions. Run "catraca help" for the commands and
// docs/cli.md for details.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// version is set at build time:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/catraca
var version = "dev"

// Exit codes.
const (
	exitOK = 0
	// exitFailed means what the command checked is wrong: an invalid
	// configuration or ruleset, failing fixtures, rules below the gate, or a
	// label the server refused.
	exitFailed = 1
	// exitUsage means the command line is wrong.
	exitUsage = 2
	// exitError means the command could not do its work: a file, the audit
	// database or the server was unavailable, or the server failed.
	exitError = 3
)

const usage = `Catraca is a self-hosted anti-abuse engine for platforms that send email.

Usage:
  catraca <command> [arguments]

Commands:
  serve          run the server
  config check   validate catraca.yaml and the ruleset it names
  rules check    validate a ruleset and print its lint warnings
  rules test     run fixture files against a ruleset
  rules gate     fail when an enforced rule is below the precision gate
  replay         backtest a ruleset on labeled events
  report         print the precision of every rule, with promote and retire candidates
  label          label a decision on a running server
  version        print the version

Run "catraca <command> -h" for the arguments of a command.

Exit codes:
  0  success
  1  a check failed: an invalid configuration or ruleset, failing fixtures,
     rules below the gate, or a label the server refused
  2  the command line is wrong
  3  the command could not run: a file, the audit database or the server
     was unavailable
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

// cli carries what every command writes to and reads from, so tests can run
// commands in process.
type cli struct {
	stdout, stderr io.Writer
	// lookupEnv reads environment variables, like os.LookupEnv.
	lookupEnv func(string) (string, bool)
	client    *http.Client
}

// getenv returns an environment variable, or "" when it is not set.
func (c *cli) getenv(name string) string {
	v, _ := c.lookupEnv(name)
	return v
}

// run runs the command in args and returns its exit code. lookupEnv reads
// the environment, both for the CATRACA_* defaults and for ${VAR} in
// catraca.yaml.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	c := &cli{stdout: stdout, stderr: stderr, lookupEnv: lookupEnv, client: &http.Client{Timeout: 30 * time.Second}}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return c.serve(ctx, rest)
	case "config":
		return c.group(ctx, "config", rest, map[string]command{"check": c.configCheck})
	case "rules":
		return c.group(ctx, "rules", rest, map[string]command{"check": c.rulesCheck, "test": c.rulesTest, "gate": c.rulesGate})
	case "replay":
		return c.replay(ctx, rest)
	case "report":
		return c.report(ctx, rest)
	case "label":
		return c.label(ctx, rest)
	case "version", "-version", "--version":
		return c.version()
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "catraca: unknown command %q\n\n%s", cmd, usage)
	return exitUsage
}

type command func(ctx context.Context, args []string) int

// group runs a subcommand of a command with subcommands, such as rules.
func (c *cli) group(ctx context.Context, name string, args []string, subs map[string]command) int {
	var names []string
	for _, n := range []string{"check", "test", "gate"} {
		if _, ok := subs[n]; ok {
			names = append(names, n)
		}
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" {
		fmt.Fprintf(c.stderr, "Usage: catraca %s <%s> [arguments]\n", name, strings.Join(names, "|"))
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	sub, ok := subs[args[0]]
	if !ok {
		fmt.Fprintf(c.stderr, "catraca %s: unknown command %q (want %s)\n", name, args[0], strings.Join(names, ", "))
		return exitUsage
	}
	return sub(ctx, args[1:])
}

// flagSet returns a FlagSet whose usage text is head followed by the flags.
func (c *cli) flagSet(name, head string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprint(c.stderr, head)
		hasFlags := false
		fs.VisitAll(func(*flag.Flag) { hasFlags = true })
		if hasFlags {
			fmt.Fprint(c.stderr, "\nFlags:\n")
			fs.PrintDefaults()
		}
	}
	return fs
}

// parse parses flags that may come before, between or after the positional
// arguments, as in "rules check rules.yaml --strict", and checks the number
// of positional arguments. It returns the exit code to use when parsing
// fails, and -1 otherwise.
func parse(fs *flag.FlagSet, args []string, minArgs, maxArgs int) ([]string, int) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, exitOK
			}
			return nil, exitUsage
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) < minArgs || (maxArgs >= 0 && len(pos) > maxArgs) {
		fs.Usage()
		return nil, exitUsage
	}
	return pos, -1
}

// failure returns exitError for problems reaching a file and exitFailed for
// problems with its content.
func failure(err error) int {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return exitError
	}
	return exitFailed
}

func (c *cli) errorf(format string, args ...any) {
	fmt.Fprintf(c.stderr, "catraca: "+format+"\n", args...)
}
