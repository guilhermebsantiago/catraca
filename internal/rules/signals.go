package rules

// signalKind is the Go type a signal has in a signal.Set.
type signalKind int

const (
	kindInt       signalKind = iota + 1 // int64
	kindFloat                           // float64
	kindBool                            // bool
	kindString                          // string
	kindStrings                         // []string
	kindStringMap                       // map[string]string
)

func (k signalKind) String() string {
	switch k {
	case kindInt:
		return "an integer"
	case kindFloat:
		return "a number"
	case kindBool:
		return "true or false"
	case kindString:
		return "a string"
	case kindStrings:
		return "a list of strings"
	case kindStringMap:
		return "a mapping of strings"
	}
	return "unknown"
}

// knownSignals are the signals the catalog computes, as listed in
// docs/design.md. Lint warns about rules that read anything else, since such
// a rule always fails to evaluate, and fixtures use the kinds to give values
// the types the catalog produces (age_hours: 2 becomes float64(2)).
var knownSignals = map[string]map[string]signalKind{
	"event": {
		"type":           kindString,
		"account_id":     kindString,
		"api_key_id":     kindString,
		"ip":             kindString,
		"from_domain":    kindString,
		"recipients":     kindInt,
		"to_domains":     kindStrings,
		"link_domains":   kindStrings,
		"links":          kindInt,
		"subject_length": kindInt,
		"feedback_kind":  kindString,
		"bounce_type":    kindString,
		"account_action": kindString,
		"attributes":     kindStringMap,
	},
	"account": {
		"sends_1m":                       kindInt,
		"sends_1h":                       kindInt,
		"sends_24h":                      kindInt,
		"sends_7d":                       kindInt,
		"recipients_1h":                  kindInt,
		"recipients_24h":                 kindInt,
		"distinct_recipient_domains_1h":  kindInt,
		"distinct_recipient_domains_24h": kindInt,
		"distinct_ips_24h":               kindInt,
		"distinct_keys_24h":              kindInt,
		"bounces_24h":                    kindInt,
		"hard_bounces_24h":               kindInt,
		"complaints_24h":                 kindInt,
		"deliveries_24h":                 kindInt,
		"bounce_rate_24h":                kindFloat,
		"hard_bounce_rate_24h":           kindFloat,
		"complaint_rate_24h":             kindFloat,
		"age_hours":                      kindFloat,
		"hourly_baseline_7d":             kindFloat,
		"volume_ratio_1h":                kindFloat,
		"new_ip":                         kindBool,
	},
	"key": {
		"sends_1m":         kindInt,
		"sends_1h":         kindInt,
		"distinct_ips_1h":  kindInt,
		"distinct_ips_24h": kindInt,
		"new_ip":           kindBool,
		"age_hours":        kindFloat,
		"leaked":           kindBool,
	},
	"ip": {
		"sends_1m":              kindInt,
		"sends_1h":              kindInt,
		"distinct_accounts_24h": kindInt,
		"distinct_keys_24h":     kindInt,
		"signups_24h":           kindInt,
	},
	"domain": {
		"sends_1h":              kindInt,
		"distinct_accounts_24h": kindInt,
		"complaints_24h":        kindInt,
	},
}

// presenceGuards name, for each map that is absent on some events, the event
// signal that says whether it is present.
var presenceGuards = []struct{ Map, Guard string }{
	{"key", "api_key_id"},
	{"ip", "ip"},
	{"domain", "from_domain"},
}
