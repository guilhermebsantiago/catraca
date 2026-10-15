package signal_test

import (
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

func TestEventSignals(t *testing.T) {
	cases := []struct {
		name string
		ev   event.Event
		want map[string]any
	}{
		{
			name: "send",
			ev: event.Event{
				Type:      event.Send,
				Time:      t0,
				AccountID: "acct-1",
				APIKeyID:  "key-1",
				IP:        "2001:DB8::1",
				From:      "News <news@Sender.Example>",
				To:        []string{"a@x.example", "b@Y.example", "c@x.example", "no-domain"},
				Subject:   "Olá 👋",
				Links: []string{
					"https://Bit.ly/abc",
					"http://bit.ly/def",
					"example.org/offer",
					"https://user@host.example:8443/p?q=1",
					"https://trailing.example./",
					"%%%",
				},
				Attributes: map[string]string{"plan": "free"},
			},
			want: map[string]any{
				"type":           "send",
				"account_id":     "acct-1",
				"api_key_id":     "key-1",
				"ip":             "2001:DB8::1",
				"from_domain":    "sender.example",
				"recipients":     int64(4),
				"to_domains":     []string{"x.example", "y.example"},
				"link_domains":   []string{"bit.ly", "example.org", "host.example", "trailing.example"},
				"links":          int64(6),
				"subject_length": int64(5),
				"feedback_kind":  "",
				"bounce_type":    "",
				"account_action": "",
				"attributes":     map[string]string{"plan": "free"},
			},
		},
		{
			name: "feedback",
			ev: event.Event{
				Type:      event.Feedback,
				Time:      t0,
				AccountID: "acct-1",
				Feedback:  &event.FeedbackInfo{Kind: event.Bounce, BounceType: "permanent"},
			},
			want: map[string]any{
				"type":           "feedback",
				"account_id":     "acct-1",
				"api_key_id":     "",
				"ip":             "",
				"from_domain":    "",
				"recipients":     int64(0),
				"to_domains":     []string{},
				"link_domains":   []string{},
				"links":          int64(0),
				"subject_length": int64(0),
				"feedback_kind":  "bounce",
				"bounce_type":    "permanent",
				"account_action": "",
				"attributes":     map[string]string{},
			},
		},
		{
			name: "account",
			ev: event.Event{
				Type:      event.Account,
				Time:      t0,
				AccountID: "acct-1",
				IP:        "198.51.100.1",
				Account:   &event.AccountInfo{Action: "signup"},
			},
			want: map[string]any{
				"type":           "account",
				"account_id":     "acct-1",
				"api_key_id":     "",
				"ip":             "198.51.100.1",
				"from_domain":    "",
				"recipients":     int64(0),
				"to_domains":     []string{},
				"link_domains":   []string{},
				"links":          int64(0),
				"subject_length": int64(0),
				"feedback_kind":  "",
				"bounce_type":    "",
				"account_action": "signup",
				"attributes":     map[string]string{},
			},
		},
	}
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		for _, tc := range cases {
			set := observe(t, c, tc.ev)
			if !reflect.DeepEqual(set.Event, tc.want) {
				t.Errorf("%s: event signals\n got %#v\nwant %#v", tc.name, set.Event, tc.want)
			}
		}
	})
}

func TestEventAttributesAreACopy(t *testing.T) {
	c := signal.NewCatalog(backends[0].new(t), signal.Options{})
	defer c.Close()
	attrs := map[string]string{"plan": "free"}
	set := observe(t, c, send(0, func(e *event.Event) { e.Attributes = attrs }))
	attrs["plan"] = "changed"
	if got := set.Event["attributes"].(map[string]string)["plan"]; got != "free" {
		t.Errorf("attributes follow the caller's map: plan = %q", got)
	}
}

// goType maps the CEL type names of Spec.Type to the Go types of values.
var goType = map[string]reflect.Type{
	"string":              reflect.TypeFor[string](),
	"int":                 reflect.TypeFor[int64](),
	"double":              reflect.TypeFor[float64](),
	"bool":                reflect.TypeFor[bool](),
	"list(string)":        reflect.TypeFor[[]string](),
	"map(string, string)": reflect.TypeFor[map[string]string](),
}

// TestSignalNamesAndTypes checks that an event that fills every map produces
// exactly the signals in Specs, with their types.
func TestSignalNamesAndTypes(t *testing.T) {
	eachBackend(t, func(t *testing.T, c signal.Catalog) {
		set := observe(t, c, send(0))
		byMap := map[string]map[string]any{
			"event": set.Event, "account": set.Account, "key": set.Key, "ip": set.IP, "domain": set.Domain,
		}
		specified := map[string][]string{}
		for _, s := range signal.Specs() {
			specified[s.Map] = append(specified[s.Map], s.Name)
			v, ok := byMap[s.Map][s.Name]
			if !ok {
				t.Errorf("%s.%s is absent", s.Map, s.Name)
				continue
			}
			if want, ok := goType[s.Type]; !ok {
				t.Errorf("%s.%s: unknown type %q", s.Map, s.Name, s.Type)
			} else if got := reflect.TypeOf(v); got != want {
				t.Errorf("%s.%s is a %v, want %v", s.Map, s.Name, got, want)
			}
		}
		for name, m := range byMap {
			got := slices.Sorted(maps.Keys(m))
			want := slices.Sorted(slices.Values(specified[name]))
			if !slices.Equal(got, want) {
				t.Errorf("%s signals = %v, want %v", name, got, want)
			}
		}
	})
}

// TestDocsListEverySignal keeps docs/signals.md in step with the catalog.
func TestDocsListEverySignal(t *testing.T) {
	doc, err := os.ReadFile("../../docs/signals.md")
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]string{}
	for _, s := range strings.Split(string(doc), "\n## ")[1:] {
		heading, body, _ := strings.Cut(s, "\n")
		sections[heading] = body
	}
	for _, s := range signal.Specs() {
		body, ok := sections["`"+s.Map+"`"]
		if !ok {
			t.Errorf("docs/signals.md has no section \"## `%s`\"", s.Map)
			continue
		}
		if !strings.Contains(body, "| `"+s.Name+"` | "+s.Type+" |") {
			t.Errorf("docs/signals.md does not list %s.%s as %s", s.Map, s.Name, s.Type)
		}
	}
}
