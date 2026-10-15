package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/guilhermebsantiago/catraca/signature"
)

// delivery is one webhook request as the platform's receiver saw it.
type delivery struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
	// Verified is what signature.Verify said: "ok", or the error.
	Verified   string    `json:"verified"`
	Status     int       `json:"status"`
	ReceivedAt time.Time `json:"received_at"`
}

// receiver is the platform side of Catraca's effect webhooks: it checks
// each request's Catraca-Signature with the public signature package and
// would revoke the key; here it records what arrived.
type receiver struct {
	url    string
	srv    *http.Server
	mu     sync.Mutex
	got    []delivery
	secret string
}

var shownHookHeaders = []string{"Content-Type", "User-Agent", signature.Header, "Catraca-Idempotency-Key", "Catraca-Attempt"}

func startReceiver(secret string) (*receiver, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &receiver{url: "http://" + l.Addr().String(), secret: secret}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/revoke-key", r.revokeKey)
	r.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = r.srv.Serve(l) }()
	return r, nil
}

func (r *receiver) revokeKey(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	d := delivery{
		Method:     req.Method,
		Path:       req.URL.Path,
		Headers:    map[string]string{},
		Body:       json.RawMessage(body),
		Verified:   "ok",
		Status:     http.StatusNoContent,
		ReceivedAt: time.Now().UTC(),
	}
	for _, h := range shownHookHeaders {
		d.Headers[h] = req.Header.Get(h)
	}
	if err := signature.Verify(r.secret, req.Header.Get(signature.Header), body, 0); err != nil {
		d.Verified, d.Status = err.Error(), http.StatusUnauthorized
	}
	r.mu.Lock()
	r.got = append(r.got, d)
	r.mu.Unlock()
	if d.Status != http.StatusNoContent {
		http.Error(w, "invalid signature", d.Status)
		return
	}
	// A real receiver revokes the key here, idempotently per
	// Catraca-Idempotency-Key.
	w.WriteHeader(http.StatusNoContent)
}

func (r *receiver) deliveries() []delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]delivery(nil), r.got...)
}

func (r *receiver) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = r.srv.Shutdown(ctx)
}
