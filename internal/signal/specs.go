package signal

import "slices"

// Spec describes one signal: where rules find it and the type of its value.
type Spec struct {
	// Map is the CEL variable the signal belongs to: event, account, key,
	// ip or domain.
	Map string
	// Name is the signal's key in its map.
	Name string
	// Type is the CEL type of the value: string, int, double, bool,
	// list(string) or map(string, string). In Go they are string, int64,
	// float64, bool, []string and map[string]string.
	Type string
}

// Specs returns every signal the catalog from NewCatalog produces, so rules
// tooling can reject a misspelled signal at load time instead of at
// evaluation.
func Specs() []Spec { return slices.Clone(specs) }

var specs = []Spec{
	{"event", "type", "string"},
	{"event", "account_id", "string"},
	{"event", "api_key_id", "string"},
	{"event", "ip", "string"},
	{"event", "from_domain", "string"},
	{"event", "recipients", "int"},
	{"event", "to_domains", "list(string)"},
	{"event", "link_domains", "list(string)"},
	{"event", "links", "int"},
	{"event", "subject_length", "int"},
	{"event", "feedback_kind", "string"},
	{"event", "bounce_type", "string"},
	{"event", "account_action", "string"},
	{"event", "attributes", "map(string, string)"},

	{"account", "sends_1m", "int"},
	{"account", "sends_1h", "int"},
	{"account", "sends_24h", "int"},
	{"account", "sends_7d", "int"},
	{"account", "recipients_1h", "int"},
	{"account", "recipients_24h", "int"},
	{"account", "distinct_recipient_domains_1h", "int"},
	{"account", "distinct_recipient_domains_24h", "int"},
	{"account", "distinct_ips_24h", "int"},
	{"account", "distinct_keys_24h", "int"},
	{"account", "bounces_24h", "int"},
	{"account", "hard_bounces_24h", "int"},
	{"account", "complaints_24h", "int"},
	{"account", "deliveries_24h", "int"},
	{"account", "bounce_rate_24h", "double"},
	{"account", "hard_bounce_rate_24h", "double"},
	{"account", "complaint_rate_24h", "double"},
	{"account", "age_hours", "double"},
	{"account", "hourly_baseline_7d", "double"},
	{"account", "volume_ratio_1h", "double"},
	{"account", "new_ip", "bool"},
	{"account", "ip_sends_24h", "int"},
	{"account", "ip_sends_7d", "int"},
	{"account", "recent_ip", "bool"},

	{"key", "sends_1m", "int"},
	{"key", "sends_1h", "int"},
	{"key", "distinct_ips_1h", "int"},
	{"key", "distinct_ips_24h", "int"},
	{"key", "new_ip", "bool"},
	{"key", "age_hours", "double"},
	{"key", "leaked", "bool"},

	{"ip", "sends_1m", "int"},
	{"ip", "sends_1h", "int"},
	{"ip", "distinct_accounts_24h", "int"},
	{"ip", "distinct_keys_24h", "int"},
	{"ip", "signups_24h", "int"},

	{"domain", "sends_1h", "int"},
	{"domain", "distinct_accounts_24h", "int"},
	{"domain", "complaints_24h", "int"},
}
