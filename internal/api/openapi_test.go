package api

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// openAPISpec is the part of docs/openapi.yaml the tests below read.
type openAPISpec struct {
	// Paths holds each path item by field: the methods, and parameters.
	Paths      map[string]map[string]yaml.Node `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Enum []string `yaml:"enum"`
		} `yaml:"schemas"`
		SecuritySchemes map[string]any `yaml:"securitySchemes"`
	} `yaml:"components"`
}

type openAPIOperation struct {
	OperationID string              `yaml:"operationId"`
	Scope       string              `yaml:"x-catraca-scope"`
	Description string              `yaml:"description"`
	Security    []map[string]any    `yaml:"security"`
	Responses   map[string]struct{} `yaml:"responses"`
}

// unscopedRoutes are the routes that take no token: the providers, which
// authenticate by signature, and health and metrics.
var unscopedRoutes = []string{
	routeFeedback,
	routeFeedbackSES,
	routeFeedbackUseSend,
	"POST /v1/secret-scanning/github",
	"GET /healthz",
	"GET /readyz",
	"GET /metrics",
}

func readOpenAPI(t *testing.T) openAPISpec {
	t.Helper()
	b, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec openAPISpec
	if err := yaml.Unmarshal(b, &spec); err != nil {
		t.Fatalf("docs/openapi.yaml: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("docs/openapi.yaml has no paths; did its format change?")
	}
	return spec
}

// operations returns the operations of the spec by route pattern, such as
// "GET /v1/decisions/{id}", the form the server registers them in.
func (spec openAPISpec) operations(t *testing.T) map[string]openAPIOperation {
	t.Helper()
	out := map[string]openAPIOperation{}
	for path, item := range spec.Paths {
		for method, node := range item {
			switch method {
			case "get", "put", "post", "delete", "patch", "head", "options", "trace":
				var op openAPIOperation
				if err := node.Decode(&op); err != nil {
					t.Fatalf("docs/openapi.yaml: %s %s: %v", method, path, err)
				}
				out[strings.ToUpper(method)+" "+path] = op
			}
		}
	}
	return out
}

// TestOpenAPIRoutes checks docs/openapi.yaml against the routes the server
// registers: every route that takes a token has an operation with its
// scope in x-catraca-scope, every other route has one without a scope,
// and every operation is a route.
func TestOpenAPIRoutes(t *testing.T) {
	spec := readOpenAPI(t)
	ops := spec.operations(t)
	s := newTestServer(t, deciderFunc(nil), nil)
	if len(s.routeScopes) == 0 {
		t.Fatal("the server registered no scoped routes")
	}

	for pattern, scope := range s.routeScopes {
		op, ok := ops[pattern]
		if !ok {
			t.Errorf("%s (scope %s) has no operation in docs/openapi.yaml", pattern, scope)
			continue
		}
		if op.Scope != string(scope) {
			t.Errorf("%s: x-catraca-scope is %q in docs/openapi.yaml, the server needs %q", pattern, op.Scope, scope)
		}
		if !strings.Contains(op.Description, "Scope: `"+string(scope)+"`") {
			t.Errorf("%s: the description in docs/openapi.yaml does not say \"Scope: `%s`\"", pattern, scope)
		}
		if op.Security != nil {
			t.Errorf("%s: overrides security in docs/openapi.yaml; a scoped route takes the bearer token", pattern)
		}
		for _, status := range []string{"401", "403"} {
			if _, ok := op.Responses[status]; !ok {
				t.Errorf("%s: no %s response in docs/openapi.yaml", pattern, status)
			}
		}
	}
	for _, pattern := range unscopedRoutes {
		op, ok := ops[pattern]
		if !ok {
			t.Errorf("%s has no operation in docs/openapi.yaml", pattern)
			continue
		}
		if op.Scope != "" {
			t.Errorf("%s takes no token, but docs/openapi.yaml gives it x-catraca-scope %q", pattern, op.Scope)
		}
		if op.Security == nil {
			t.Errorf("%s takes no token, but docs/openapi.yaml leaves it the bearer token: set its security", pattern)
		}
		for _, req := range op.Security {
			for name := range req {
				if name == "bearerToken" {
					t.Errorf("%s takes no token, but docs/openapi.yaml asks for one", pattern)
				}
			}
		}
	}

	ids := map[string]string{}
	for pattern, op := range ops {
		_, scoped := s.routeScopes[pattern]
		if !scoped && !slices.Contains(unscopedRoutes, pattern) {
			t.Errorf("docs/openapi.yaml has %s, which the server does not serve", pattern)
		}
		if op.OperationID == "" {
			t.Errorf("%s: no operationId in docs/openapi.yaml", pattern)
		} else if other, dup := ids[op.OperationID]; dup {
			t.Errorf("%s and %s share operationId %s", pattern, other, op.OperationID)
		}
		ids[op.OperationID] = pattern
	}
}

// TestOpenAPIScopes checks the scopes docs/openapi.yaml uses are the
// server's.
func TestOpenAPIScopes(t *testing.T) {
	for pattern, op := range readOpenAPI(t).operations(t) {
		if op.Scope != "" && scopeBit(Scope(op.Scope)) == 0 {
			t.Errorf("%s: x-catraca-scope %q is not one of %v", pattern, op.Scope, Scopes)
		}
	}
}

// TestOpenAPIErrorCodes checks the ErrorCode enum of docs/openapi.yaml
// against the error table of docs/api.md, both ways.
func TestOpenAPIErrorCodes(t *testing.T) {
	schema, ok := readOpenAPI(t).Components.Schemas["ErrorCode"]
	if !ok || len(schema.Enum) == 0 {
		t.Fatal("docs/openapi.yaml has no ErrorCode enum")
	}
	documented := documentedErrors(t)
	inSpec := map[string]bool{}
	for _, code := range schema.Enum {
		if inSpec[code] {
			t.Errorf("ErrorCode in docs/openapi.yaml lists %s twice", code)
		}
		inSpec[code] = true
		if _, ok := documented[code]; !ok {
			t.Errorf("ErrorCode in docs/openapi.yaml lists %s, which the error table of docs/api.md does not", code)
		}
	}
	for _, code := range slices.Sorted(maps.Keys(documented)) {
		if !inSpec[code] {
			t.Errorf("docs/api.md lists %s, which the ErrorCode enum of docs/openapi.yaml does not", code)
		}
	}
}
