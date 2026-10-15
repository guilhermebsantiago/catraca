// Command demo plays a scripted scenario against a real Catraca server and
// saves what the server answered, for the launch video in media/.
//
// It builds cmd/catraca (or uses -catraca), writes a temporary configuration
// (memory store, SQLite audit log, a revoke_key hook, the generic feedback
// endpoint) into a temporary directory, runs `catraca serve` there, starts a
// small webhook receiver that verifies Catraca's signatures with the public
// signature package, and then plays the scenario in scenario.go. Every
// request and answer the video shows is written to -out as it was sent and
// received. Run it from the repository root:
//
//	go run ./examples/demo
//
// See examples/demo/README.md.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	bin := flag.String("catraca", "", "a catraca binary to run; when empty, ./cmd/catraca is built into the temporary directory")
	out := flag.String("out", filepath.Join("examples", "demo", "out"), "directory for the recorded output")
	keep := flag.Bool("keep", false, "keep the temporary directory (configuration, audit database, server log)")
	flag.Parse()
	log.SetFlags(0)
	if err := run(*bin, *out, *keep); err != nil {
		log.Fatalf("demo: %v", err)
	}
}

func run(bin, out string, keep bool) (err error) {
	if _, err := os.Stat(filepath.Join("cmd", "catraca")); err != nil {
		return errors.New("run the demo from the repository root: go run ./examples/demo")
	}
	tmp, err := os.MkdirTemp("", "catraca-demo-")
	if err != nil {
		return err
	}
	if keep {
		log.Printf("temporary directory: %s", tmp)
	} else {
		defer os.RemoveAll(tmp)
	}

	if bin == "" {
		bin = filepath.Join(tmp, "catraca"+exeSuffix())
		log.Printf("building ./cmd/catraca")
		build := exec.Command("go", "build", "-o", bin, "./cmd/catraca")
		build.Stdout, build.Stderr = os.Stderr, os.Stderr
		if err := build.Run(); err != nil {
			return fmt.Errorf("go build: %w", err)
		}
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return err
	}

	s := &session{
		bin:            bin,
		dir:            tmp,
		token:          randomHex(32),
		hookSecret:     randomHex(32),
		feedbackSecret: randomHex(32),
		client:         &http.Client{Timeout: 10 * time.Second},
	}

	// The receiver stands in for the platform's webhook endpoint.
	recv, err := startReceiver(s.hookSecret)
	if err != nil {
		return err
	}
	defer recv.close()

	// The ruleset is copied next to the configuration, so every path the
	// recorded commands show is relative to the temporary directory.
	rules, err := os.ReadFile(filepath.Join("examples", "demo", "rules.yaml"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "rules.yaml"), rules, 0o644); err != nil {
		return err
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	s.base = fmt.Sprintf("http://127.0.0.1:%d", port)
	config := fmt.Sprintf(configTemplate, port, recv.url+"/hooks/revoke-key")
	if err := os.WriteFile(filepath.Join(tmp, "catraca.yaml"), []byte(config), 0o644); err != nil {
		return err
	}

	stop, err := s.serve()
	if err != nil {
		return err
	}
	defer func() {
		if serr := stop(); serr != nil && err == nil {
			err = serr
		}
	}()

	rec, err := play(s, recv)
	if err != nil {
		return err
	}
	return rec.write(out)
}

// configTemplate is the temporary catraca.yaml. Secrets come from the
// environment of the server process, as in production.
const configTemplate = `# Written by examples/demo into a temporary directory.
server:
  listen: 127.0.0.1:%d
auth:
  tokens:
    - name: demo
      token: ${DEMO_API_TOKEN}
rules:
  path: rules.yaml
store:
  backend: memory
audit:
  dsn: sqlite:audit.db
# The default 10ms is right for a server; a laptop playing the scenario while
# it writes the audit log can miss it now and then, and a degraded decision
# skips the rules it cannot evaluate. The demo records none.
engine:
  deadline: 250ms
hooks:
  - name: revoke_key
    url: %s
    secret: ${DEMO_HOOK_SECRET}
    timeout: 5s
feedback:
  generic:
    secret: ${DEMO_FEEDBACK_SECRET}
logging:
  level: info
  format: json
`

// session is a running server and what the scenario needs to talk to it.
type session struct {
	bin, dir, base string
	token          string
	hookSecret     string
	feedbackSecret string
	client         *http.Client
}

func (s *session) env() []string {
	return append(os.Environ(),
		"DEMO_API_TOKEN="+s.token,
		"DEMO_HOOK_SECRET="+s.hookSecret,
		"DEMO_FEEDBACK_SECRET="+s.feedbackSecret,
		"CATRACA_TOKEN="+s.token,
		"CATRACA_SERVER="+s.base,
	)
}

// serve starts `catraca serve` and waits until it is ready. The returned
// function stops it.
func (s *session) serve() (func() error, error) {
	logFile, err := os.Create(filepath.Join(s.dir, "serve.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(s.bin, "serve", "-config", "catraca.yaml")
	cmd.Dir = s.dir
	cmd.Env = s.env()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, err
	}
	log.Printf("catraca serve: pid %d on %s", cmd.Process.Pid, s.base)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stop := func() error {
		defer logFile.Close()
		// A graceful stop where the platform supports it; Windows has no
		// SIGINT for another process, so the server is killed there. The
		// audit log has been read by then.
		if runtime.GOOS == "windows" || cmd.Process.Signal(os.Interrupt) != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		log.Printf("catraca serve: stopped")
		return nil
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := s.client.Get(s.base + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return stop, nil
			}
		}
		select {
		case err := <-done:
			logFile.Close()
			tail, _ := os.ReadFile(logFile.Name())
			return nil, fmt.Errorf("catraca serve exited: %v\n%s", err, tail)
		default:
		}
		if time.Now().After(deadline) {
			_ = stop()
			return nil, errors.New("catraca serve did not become ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// exchange is one HTTP request and its answer, as the video shows them.
type exchange struct {
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	Request         json.RawMessage   `json:"request,omitempty"`
	Status          int               `json:"status"`
	StatusText      string            `json:"status_text"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	Response        json.RawMessage   `json:"response"`
}

// keptHeaders are the response headers worth showing.
var keptHeaders = []string{"Content-Type", "Retry-After", "X-Request-Id"}

// do sends body to path. Routes under /v1 other than feedback get the API
// token; extra headers (such as a signature) are recorded.
func (s *session) do(method, path string, body []byte, headers map[string]string) (*exchange, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/v1/feedback") {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ex := &exchange{
		Method:          method,
		Path:            path,
		RequestHeaders:  headers,
		Status:          resp.StatusCode,
		StatusText:      http.StatusText(resp.StatusCode),
		ResponseHeaders: map[string]string{},
		Response:        json.RawMessage(bytes.TrimSpace(data)),
	}
	if body != nil {
		ex.Request = json.RawMessage(body)
	}
	for _, h := range keptHeaders {
		if v := resp.Header.Get(h); v != "" {
			ex.ResponseHeaders[h] = v
		}
	}
	if resp.StatusCode >= 300 {
		return ex, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, data)
	}
	return ex, nil
}

// command is one run of the catraca command line.
type command struct {
	Args   []string `json:"args"`
	Stdout string   `json:"stdout"`
	Exit   int      `json:"exit"`
}

// cli runs the catraca binary in the temporary directory, with the API
// token and server address in the environment, as an operator would.
func (s *session) cli(args ...string) (command, error) {
	cmd := exec.Command(s.bin, args...)
	cmd.Dir = s.dir
	cmd.Env = s.env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	c := command{Args: append([]string{"catraca"}, args...), Stdout: stdout.String()}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		c.Exit = exit.ExitCode()
		return c, fmt.Errorf("%s: exit %d: %s", strings.Join(c.Args, " "), c.Exit, stderr.String())
	}
	return c, err
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(ctx context.Context, timeout time.Duration, cond func() bool) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for !cond() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(25 * time.Millisecond):
		}
	}
	return true
}
