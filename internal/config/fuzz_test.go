package config

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

// FuzzParse parses any YAML as a configuration, with a fixed environment.
// Parse never panics, fails only with a non-empty ErrorList whose entries
// say something, and parses the same file the same way twice.
func FuzzParse(f *testing.F) {
	for _, name := range []string{"../../catraca.example.yaml", "../../deploy/catraca.yaml", "../../deploy/catraca.compose.yaml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, seed := range []string{
		minimal,
		"",
		"~",
		"[]",
		"server: {listen: ':8080', drain_delay: 5s, max_body_bytes: 1_048_576}\n" + minimal,
		"auth:\n  tokens:\n    - &t {name: a, token: ${CATRACA_API_TOKEN}}\n    - *t\n",
		"auth: {tokens: [{name: a, token: ${UNSET}}]}\n",
		"auth: {tokens: [{name: a, token: '$${literal}${EMPTY:-fallback}'}]}\n",
		"store: {redis: {url: 'redis://:p@localhost:6379/0', mode: cluster}}\n" + minimal,
		"hooks:\n  - {name: revoke_key, url: 'https://x.example/h', secret: ${CATRACA_HOOK_SECRET}, headers: {Authorization: Bearer x, Authorization: y}}\n" + minimal,
		"gate: {min_labeled: 9223372036854775808, min_precision: NaN}\n" + minimal,
		"engine: {deadline: -1ms, max_event_age: 1e9h}\n" + minimal,
		"<<: {server: {listen: x}}\n" + minimal,
		"server:\n  listen: !!binary aGVsbG8=\n" + minimal,
		"? [a]\n: b\n",
	} {
		f.Add([]byte(seed))
	}
	lookup := env(map[string]string{
		"CATRACA_API_TOKEN":       testToken,
		"CATRACA_HOOK_SECRET":     testSecret,
		"CATRACA_FEEDBACK_SECRET": testSecret,
		"EMPTY":                   "",
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data, "", lookup)
		if err != nil {
			var list ErrorList
			if !errors.As(err, &list) || len(list) == 0 {
				t.Fatalf("Parse error %v (%T) is not a non-empty ErrorList", err, err)
			}
			for _, e := range list {
				if e.Msg == "" {
					t.Errorf("an error without a message: %+v", e)
				}
			}
			return
		}
		again, err := Parse(data, "", lookup)
		if err != nil || !reflect.DeepEqual(again, cfg) {
			t.Fatalf("parsing again: %+v, %v; first %+v", again, err, cfg)
		}
	})
}
