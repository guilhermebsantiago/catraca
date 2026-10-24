package event

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fullSend is a valid send event with every field a send carries.
func fullSend() Event {
	return Event{
		ID: "evt_1", Type: Send, AccountID: "acct_1", APIKeyID: "key_1", IP: "2001:db8::1",
		From: "News <news@shop.example>", To: []string{"ana@mail.example", "bo@mail.example"},
		Subject: "Your receipt", Links: []string{"https://shop.example/r/1"},
		Attributes: map[string]string{"plan": "free", "template": "receipt"},
	}
}

func addresses(n int) []string {
	to := make([]string, n)
	for i := range to {
		to[i] = fmt.Sprintf("u%d@d%d.example", i, i)
	}
	return to
}

func attributes(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("k%d", i)] = "v"
	}
	return m
}

func TestValidateRequiredFields(t *testing.T) {
	tests := []struct {
		ev   Event
		want string
	}{
		{Event{}, "event: type is required"},
		{Event{Type: "teleport", AccountID: "a"}, "event: unknown type teleport"},
		{Event{Type: Send}, "event: account_id is required"},
		{Event{Type: Feedback, AccountID: "a"}, "event: feedback events need a feedback object"},
		{Event{Type: KeyLeak}, "event: key_leak events need api_key_id"},
	}
	for _, tt := range tests {
		err := tt.ev.Validate()
		if err == nil || err.Error() != tt.want || !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%+v) = %v, want %q wrapping ErrInvalid", tt.ev, err, tt.want)
		}
	}
	for _, ev := range []Event{
		fullSend(),
		{Type: KeyLeak, APIKeyID: "key_1"},
		{Type: Feedback, AccountID: "a", Feedback: &FeedbackInfo{Kind: Bounce}},
		{Type: Account, AccountID: "a", Account: &AccountInfo{Action: "signup"}},
	} {
		if err := ev.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", ev, err)
		}
	}
}

func TestValidateLimits(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	tests := []struct {
		name   string
		change func(*Event)
		want   string // "" when the event is valid
	}{
		{"id at the limit", func(e *Event) { e.AccountID = long(MaxIDBytes) }, ""},
		{"account_id too long", func(e *Event) { e.AccountID = long(MaxIDBytes + 1) }, "account_id is 257 bytes; at most 256 are accepted"},
		{"id too long", func(e *Event) { e.ID = long(300) }, "id is 300 bytes"},
		{"api_key_id too long", func(e *Event) { e.APIKeyID = long(300) }, "api_key_id is 300 bytes"},
		{"ip too long", func(e *Event) { e.IP = long(300) }, "ip is 300 bytes"},

		{"recipients at the limit", func(e *Event) { e.To = addresses(MaxRecipients) }, ""},
		{"too many recipients", func(e *Event) { e.To = addresses(MaxRecipients + 1) }, "to has 1001 addresses; at most 1000 are accepted"},
		{"links at the limit", func(e *Event) { e.Links = addresses(MaxLinks) }, ""},
		{"too many links", func(e *Event) { e.Links = addresses(MaxLinks + 1) }, "links has 1001 links; at most 1000 are accepted"},
		{"attributes at the limit", func(e *Event) { e.Attributes = attributes(MaxAttributes) }, ""},
		{"too many attributes", func(e *Event) { e.Attributes = attributes(MaxAttributes + 1) }, "attributes has 65 entries; at most 64 are accepted"},

		{"text at the limit", func(e *Event) { e.Subject = long(MaxTextBytes) }, ""},
		{"subject too long", func(e *Event) { e.Subject = long(MaxTextBytes + 1) }, "subject is 8193 bytes; at most 8192 are accepted"},
		{"address too long", func(e *Event) { e.To[1] = long(MaxTextBytes + 1) }, "to[1] is 8193 bytes"},
		{"link too long", func(e *Event) { e.Links[0] = "https://x.example/?q=" + long(MaxTextBytes) }, "links[0] is"},
		{"attribute value too long", func(e *Event) { e.Attributes["plan"] = long(MaxTextBytes + 1) }, `attributes["plan"] is 8193 bytes`},
		{"attribute name too long", func(e *Event) { e.Attributes = map[string]string{long(300): "v"} }, "attribute name \"xxxx"},

		{"NUL in account_id", func(e *Event) { e.AccountID = "acct\x00" }, "account_id contains the control character U+0000"},
		{"newline in api_key_id", func(e *Event) { e.APIKeyID = "key\n1" }, "api_key_id contains the control character U+000A"},
		{"escape in id", func(e *Event) { e.ID = "\x1b[31mevt" }, "id contains the control character U+001B"},
		{"DEL in ip", func(e *Event) { e.IP = "203.0.113.7\x7f" }, "ip contains the control character U+007F"},
		{"C1 control in account_id", func(e *Event) { e.AccountID = "acct\u0085" }, "account_id contains the control character U+0085"},
		{"invalid UTF-8 in account_id", func(e *Event) { e.AccountID = "acct\xff" }, "account_id is not valid UTF-8"},
		{"control character in attribute name", func(e *Event) { e.Attributes = map[string]string{"pl\x01an": "v"} }, `attribute name "pl\x01an" contains the control character U+0001`},

		{"NUL in subject", func(e *Event) { e.Subject = "hi\x00" }, "subject contains NUL (U+0000)"},
		{"NUL in from", func(e *Event) { e.From = "a\x00@b.example" }, "from contains NUL"},
		{"NUL in a recipient", func(e *Event) { e.To[0] = "a\x00@b.example" }, "to[0] contains NUL"},
		{"NUL in a link", func(e *Event) { e.Links[0] = "https://x.example/\x00" }, "links[0] contains NUL"},
		{"NUL in an attribute value", func(e *Event) { e.Attributes["plan"] = "\x00" }, `attributes["plan"] contains NUL`},
		{"NUL in feedback", func(e *Event) { e.Feedback = &FeedbackInfo{Kind: Bounce, Recipient: "a\x00@b.example"} }, "feedback.recipient contains NUL"},
		{"NUL in a message id", func(e *Event) { e.Feedback = &FeedbackInfo{Kind: Bounce, MessageID: "\x00"} }, "feedback.message_id contains NUL"},
		{"NUL in account info", func(e *Event) { e.Account = &AccountInfo{Plan: "pro\x00"} }, "account.plan contains NUL"},
		{"NUL in leak info", func(e *Event) { e.Leak = &LeakInfo{URL: "https://github.com/\x00"} }, "leak.url contains NUL"},

		// What real platforms send must stay valid: a false positive is a
		// bug.
		{"tabs and newlines in text", func(e *Event) { e.Subject = "Line one\r\n\tline two"; e.From = "\tNews <news@shop.example>\n" }, ""},
		{"unicode ids", func(e *Event) { e.AccountID = "conta-ação-日本"; e.APIKeyID = "chave_🔑" }, ""},
		{"an email address as account id", func(e *Event) { e.AccountID = long(64) + "@" + long(189) }, ""},
		{"an IPv6 address with a zone", func(e *Event) { e.IP = "fe80::1%eth0" }, ""},
		{"a forwarded-for chain as ip", func(e *Event) { e.IP = "203.0.113.7, 10.0.0.1, 10.0.0.2" }, ""},
		{"empty attribute value", func(e *Event) { e.Attributes["plan"] = "" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := fullSend()
			tt.change(&ev)
			err := ev.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), "event: "+tt.want) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v, want %q wrapping ErrInvalid", err, "event: "+tt.want+"...")
			}
		})
	}
}

// TestNormalizeKeepsLimits normalizes addresses at the limit whose
// lowercase takes more bytes: a valid event must stay valid. JSON cannot
// carry invalid UTF-8, which FuzzEvent decodes from, but an event built in
// Go can.
func TestNormalizeKeepsLimits(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for _, s := range []string{
		strings.Repeat("Ⱥ", MaxTextBytes/2),
		strings.Repeat("\xff", MaxTextBytes),
		" " + strings.Repeat("Ⱦ", MaxTextBytes/2-2) + "A ",
	} {
		ev := Event{Type: Feedback, AccountID: "a", From: s, To: []string{s}, Feedback: &FeedbackInfo{Kind: Bounce, Recipient: s}}
		if err := ev.Validate(); err != nil {
			t.Fatal(err)
		}
		ev.Normalize(now)
		if err := ev.Validate(); err != nil {
			t.Errorf("normalized: %v", err)
		}
		if want := strings.TrimSpace(s); ev.From != want || ev.To[0] != want || ev.Feedback.Recipient != want {
			t.Errorf("an address whose lowercase is too long changed to %.20q..., want it only trimmed", ev.From)
		}
	}
	// Below the limit, the same letters are lowercased.
	ev := Event{From: " ȺȾ@X.EXAMPLE "}
	ev.Normalize(now)
	if ev.From != "ⱥⱦ@x.example" {
		t.Errorf("From = %q, want it lowercased", ev.From)
	}
}

// Validate runs on every decision, so a valid event must cost no allocation.
func TestValidateDoesNotAllocate(t *testing.T) {
	ev := fullSend()
	ev.Feedback = &FeedbackInfo{Kind: Bounce, Recipient: "ana@mail.example"}
	ev.Account = &AccountInfo{Action: "signup"}
	ev.Leak = &LeakInfo{Source: "github"}
	if n := testing.AllocsPerRun(100, func() {
		if err := ev.Validate(); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Errorf("Validate allocated %v times, want 0", n)
	}
}
