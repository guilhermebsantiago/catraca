package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// errorBody is the shape of every error the /v1 routes return.
type errorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	// Code is a stable, machine-readable name for the problem.
	Code string `json:"code"`
	// Message explains the problem to a person.
	Message string `json:"message"`
	// Details lists individual problems, such as each error in a ruleset
	// that failed to load.
	Details []string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{apiError{Code: code, Message: msg}})
}

// readJSON decodes the request body into v, strictly: unknown fields and
// trailing data are errors, so a misspelled field is reported instead of
// silently ignored. It answers the request itself and returns false when the
// body is not acceptable.
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.maxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, extra := dec.Token(); extra != io.EOF {
			err = errTrailing
			var tooLarge *http.MaxBytesError
			if errors.As(extra, &tooLarge) {
				err = extra
			}
		}
	}
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large",
			fmt.Sprintf("the body is larger than %d bytes", tooLarge.Limit))
		return false
	}
	writeError(w, http.StatusBadRequest, "invalid_json", jsonProblem(err))
	return false
}

var errTrailing = errors.New("the body must hold a single JSON value")

// jsonProblem describes a decoding error without Go type names.
func jsonProblem(err error) string {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	var parse *time.ParseError
	switch {
	case errors.Is(err, io.EOF):
		return "the body is empty; send a JSON object"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "the JSON body is truncated"
	case errors.As(err, &syntax):
		return fmt.Sprintf("invalid JSON at byte %d: %s", syntax.Offset, syntax.Error())
	case errors.As(err, &typ):
		field := typ.Field
		if field == "" {
			field = "the body"
		}
		return fmt.Sprintf("%s: want %s, got a JSON %s", field, kindOf(typ.Type), typ.Value)
	case errors.As(err, &parse):
		return fmt.Sprintf("invalid time %s: want RFC 3339, such as 2026-10-15T12:00:00Z", parse.Value)
	}
	return strings.TrimPrefix(err.Error(), "json: ")
}

var timeType = reflect.TypeFor[time.Time]()

func kindOf(t reflect.Type) string {
	if t == timeType {
		return "an RFC 3339 time string"
	}
	switch t.Kind() {
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "true or false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "an integer"
	case reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.Slice, reflect.Array:
		return "a list"
	case reflect.Map, reflect.Struct:
		return "an object"
	case reflect.Pointer:
		return kindOf(t.Elem())
	}
	return "another type"
}
