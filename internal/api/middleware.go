package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// RequestIDHeader carries the request id. A valid id sent by the client is
// kept, so a request can be traced across the platform and Catraca;
// otherwise one is generated.
const RequestIDHeader = "X-Request-Id"

// reqInfo is what the middleware learns about a request while it is served.
// Handlers fill it in through the context.
type reqInfo struct {
	id string
	// route is the pattern that matched, or "unmatched".
	route string
	// client is the name of the token the request authenticated with.
	client string
	// attrs are added to the access log line, for example a decision id.
	attrs []slog.Attr
}

type infoKey struct{}

func infoFrom(ctx context.Context) *reqInfo {
	ri, _ := ctx.Value(infoKey{}).(*reqInfo)
	return ri
}

// annotate adds attributes to the request's access log line.
func annotate(r *http.Request, attrs ...slog.Attr) {
	if ri := infoFrom(r.Context()); ri != nil {
		ri.attrs = append(ri.attrs, attrs...)
	}
}

// ServeHTTP assigns the request id, recovers panics, routes the request, and
// logs and measures it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	ri := &reqInfo{id: requestID(r.Header.Get(RequestIDHeader)), route: "unmatched"}
	rw := &responseWriter{ResponseWriter: w}
	rw.Header().Set(RequestIDHeader, ri.id)
	r = r.WithContext(context.WithValue(r.Context(), infoKey{}, ri))

	defer func() {
		v := recover()
		if v != nil && v != http.ErrAbortHandler {
			s.log.ErrorContext(r.Context(), "panic serving request",
				"request_id", ri.id, "route", ri.route, "panic", v, "stack", string(debug.Stack()))
			if !rw.wroteHeader {
				writeError(rw, http.StatusInternalServerError, "internal", "internal error")
			}
		}
		s.finish(r, rw, ri, s.now().Sub(start))
		if v == http.ErrAbortHandler {
			panic(v)
		}
	}()
	s.mux.ServeHTTP(rw, r)
}

// quietRoutes are polled by probes and scrapers; their access logs are
// debug level so they do not drown the rest.
var quietRoutes = map[string]bool{"GET /healthz": true, "GET /readyz": true, "GET /metrics": true}

func (s *Server) finish(r *http.Request, rw *responseWriter, ri *reqInfo, elapsed time.Duration) {
	status := rw.statusCode()
	s.duration.WithLabelValues(ri.route, strconv.Itoa(status)).Observe(elapsed.Seconds())

	level := slog.LevelInfo
	if quietRoutes[ri.route] {
		level = slog.LevelDebug
	}
	if !s.log.Enabled(r.Context(), level) {
		return
	}
	attrs := append([]slog.Attr{
		slog.String("request_id", ri.id),
		slog.String("method", r.Method),
		slog.String("route", ri.route),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.Int64("bytes", rw.bytes),
		slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000),
		slog.String("remote", r.RemoteAddr),
	}, ri.attrs...)
	if ri.client != "" {
		attrs = append(attrs, slog.String("client", ri.client))
	}
	s.log.LogAttrs(r.Context(), level, "request", attrs...)
}

// requestID returns the client's id when it is safe to log and echo, and a
// new random id otherwise.
func requestID(sent string) string {
	if n := len(sent); n > 0 && n <= 128 && strings.Trim(sent, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:") == "" {
		return sent
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// authed requires a valid bearer token.
func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, problem := s.authenticate(r.Header.Get("Authorization"))
		if problem != "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="catraca"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", problem)
			return
		}
		if ri := infoFrom(r.Context()); ri != nil {
			ri.client = name
		}
		h(w, r)
	})
}

// authenticate returns the name of the token in an Authorization header, or
// why the header is not acceptable. Tokens are compared as SHA-256 sums in
// constant time, and every configured token is compared, so neither the
// time taken nor an early exit tells a caller how close a guess was or which
// token it matched.
func (s *Server) authenticate(header string) (name, problem string) {
	if header == "" {
		return "", "missing bearer token: send Authorization: Bearer <token>"
	}
	scheme, token, ok := strings.Cut(header, " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", "the Authorization header must be Bearer <token>"
	}
	sum := sha256.Sum256([]byte(token))
	match := -1
	for i := range s.tokens {
		if subtle.ConstantTimeCompare(sum[:], s.tokens[i].sum[:]) == 1 {
			match = i
		}
	}
	if match < 0 {
		return "", "invalid bearer token"
	}
	return s.tokens[match].name, ""
}

// responseWriter records the status and size of a response.
type responseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *responseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush supports streaming handlers.
func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriter) statusCode() int {
	if !w.wroteHeader {
		// Nothing was written: net/http answers 200 with an empty body.
		return http.StatusOK
	}
	return w.status
}
