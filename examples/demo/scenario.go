package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/guilhermebsantiago/catraca/signature"
)

// The scenario, in event time:
//
//  1. History, the 24 hours before the demo, sent with explicit event times:
//     four established accounts sending as usual, a signup farm creating
//     accounts from one IP (signup-farm-ip matches in shadow), and new
//     accounts linking through a URL shortener (shortener-links-new-account,
//     enforced in the demo ruleset, flags them).
//  2. Live, at the wall clock, recorded in order as the lane: normal traffic
//     (allow); a brand-new account bursting (throttle with Retry-After);
//     complaints through the generic feedback endpoint until the newsletter
//     account's complaint rate passes 0.3% (hold), after which it stops
//     sending; a key reported leaked and the next send with it (block, and a
//     signed revoke_key webhook, after which the account uses a new key);
//     the last signups of the farm (shadow).
//  3. Labels, through the API and `catraca label`, then `catraca report`.

// Event is an event in the API's format (docs/api.md).
type Event struct {
	Type      string    `json:"type,omitempty"`
	AccountID string    `json:"account_id,omitempty"`
	APIKeyID  string    `json:"api_key_id,omitempty"`
	IP        string    `json:"ip,omitempty"`
	From      string    `json:"from,omitempty"`
	To        []string  `json:"to,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Links     []string  `json:"links,omitempty"`
	Feedback  *Feedback `json:"feedback,omitempty"`
	Account   *Account  `json:"account,omitempty"`
	Leak      *Leak     `json:"leak,omitempty"`
	Time      string    `json:"time,omitempty"`
}

// Feedback is a delivery outcome.
type Feedback struct {
	Kind       string `json:"kind"`
	BounceType string `json:"bounce_type,omitempty"`
	Recipient  string `json:"recipient,omitempty"`
	MessageID  string `json:"message_id,omitempty"`
}

// Account is account activity.
type Account struct {
	Action    string `json:"action,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// Leak says where a leaked key was found.
type Leak struct {
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
}

// Decision is the part of Catraca's answer the scenario reads.
type Decision struct {
	ID         string  `json:"id"`
	Action     string  `json:"action"`
	RetryAfter int64   `json:"retry_after"`
	Matches    []Match `json:"matches"`
	Shadow     []Match `json:"shadow"`
	LatencyUS  int64   `json:"latency_us"`
	Version    string  `json:"ruleset_version"`
	Degraded   bool    `json:"degraded"`
}

// Match is a rule that matched.
type Match struct {
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
	Mode   string `json:"mode"`
}

// laneEntry is one live decision, in the order Catraca made them.
type laneEntry struct {
	Seq        int         `json:"seq"`
	Phase      string      `json:"phase"`
	Type       string      `json:"type"`
	AccountID  string      `json:"account_id"`
	APIKeyID   string      `json:"api_key_id,omitempty"`
	DecisionID string      `json:"decision_id"`
	Action     string      `json:"action"`
	RetryAfter int64       `json:"retry_after,omitempty"`
	Rules      []string    `json:"rules,omitempty"`
	Shadow     []laneMatch `json:"shadow,omitempty"`
	LatencyUS  int64       `json:"latency_us"`
}

type laneMatch struct {
	RuleID string `json:"rule_id"`
	Action string `json:"action"`
}

// complaintRound is one complaint and the newsletter account's next send.
type complaintRound struct {
	Complaints int    `json:"complaints"`
	Action     string `json:"next_send_action"`
	DecisionID string `json:"next_send_decision_id"`
}

// record is everything written to the output directory.
type record struct {
	Note        string               `json:"note"`
	GeneratedAt time.Time            `json:"generated_at"`
	Version     string               `json:"catraca_version"`
	Ruleset     string               `json:"ruleset_version"`
	History     map[string]int       `json:"history"`
	Steps       map[string]*exchange `json:"steps"`
	Burst       map[string]int       `json:"burst"`
	Complaints  []complaintRound     `json:"complaints"`
	Hook        *delivery            `json:"hook"`
	Labels      map[string]int       `json:"labels"`
	CLI         map[string]command   `json:"cli"`
	Lane        []laneEntry          `json:"lane"`
}

// sender is an established account with a steady daily volume.
type sender struct {
	account, key, ip, from, subject string
	created                         time.Time
	perDay                          int
}

var established = []sender{
	{"acct_lumen", "key_4f1a", "203.0.113.10", "receipts@lumen.example", "Your receipt #%d", date(2023, 3, 14), 320},
	{"acct_fernway", "key_7b3d", "203.0.113.24", "news@fernway.example", "Fernway weekly, issue %d", date(2024, 1, 9), 1180},
	{"acct_tidal", "key_9c2e", "203.0.113.37", "alerts@tidal.example", "Alert %d: disk above 90%% on db-2", date(2022, 11, 2), 210},
	{"acct_okapi", "key_2e8b", "203.0.113.52", "hello@okapi.example", "Your Okapi invoice %d", date(2025, 6, 20), 140},
}

const (
	farmIP       = "198.51.100.77"
	farmHistory  = 61 // signups before the demo; 3 more arrive live
	burstAccount = "acct_x7q2"
	burstKey     = "key_5d0c"
	burstIP      = "198.51.100.23"
	burstSends   = 140
	leakedKey    = "key_9c2e" // acct_tidal's
	rotatedKey   = "key_b61e" // its replacement
	attackerIP   = "192.0.2.200"
	shortenerNew = 10 // new accounts that link through bit.ly; the last sends live
)

var (
	names   = []string{"ana", "bruno", "carla", "diego", "elena", "felipe", "gabi", "hugo", "iris", "joao", "kai", "lia", "marta", "nina", "otto", "paula", "rafa", "sofia", "tomas", "vera"}
	domains = []string{"mail.example", "inbox.example", "post.example", "box.example", "letters.example"}
)

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 9, 0, 0, 0, time.UTC) }

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// scenario holds what a run has seen so far.
type scenario struct {
	s     *session
	rng   *rand.Rand
	rec   *record
	seq   int
	phase string
	// Decision ids by what the labels need.
	farm      []string // signup-farm-ip shadow matches, in order
	shortener []string // shortener-links-new-account matches, in order
	throttles []string
	hold      string
	block     string
	counter   map[string]int
	// active are the established accounts still sending: a held account
	// stops, and a revoked key is replaced.
	active []sender
	recv   *receiver
}

func play(s *session, recv *receiver) (*record, error) {
	sc := &scenario{
		s:   s,
		rng: rand.New(rand.NewPCG(2026, 10)),
		rec: &record{
			Note: "Recorded by examples/demo against a real catraca serve with examples/demo/rules.yaml. " +
				"Ids, times and latencies change on every run.",
			GeneratedAt: time.Now().UTC().Truncate(time.Second),
			History:     map[string]int{},
			Steps:       map[string]*exchange{},
			Burst:       map[string]int{},
			Labels:      map[string]int{},
			CLI:         map[string]command{},
		},
		counter: map[string]int{},
		active:  slices.Clone(established),
		recv:    recv,
	}
	v, err := s.cli("version")
	if err != nil {
		return nil, err
	}
	sc.rec.Version = strings.TrimSpace(v.Stdout)

	log.Printf("history: the 24 hours before now")
	if err := sc.history(time.Now().UTC().Truncate(time.Second)); err != nil {
		return nil, err
	}
	log.Printf("live: flow, burst, complaints, leak, shadow")
	for _, phase := range []func() error{sc.flow, sc.burst, sc.complaints, sc.leak, sc.shadow} {
		if err := phase(); err != nil {
			return nil, err
		}
	}
	if err := sc.label(); err != nil {
		return nil, err
	}
	// Decisions reach the audit log in batches every 200 ms; give the last
	// batch time to land before reading the database from another process.
	time.Sleep(time.Second)
	report, err := s.cli("report", "--rules", "rules.yaml", "--audit", "sqlite:audit.db")
	if err != nil {
		return nil, err
	}
	sc.rec.CLI["report"] = report
	reportJSON, err := s.cli("report", "--rules", "rules.yaml", "--audit", "sqlite:audit.db", "--json")
	if err != nil {
		return nil, err
	}
	sc.rec.CLI["report_json"] = reportJSON
	fmt.Fprint(os.Stderr, report.Stdout)
	return sc.rec, nil
}

// --- history ---------------------------------------------------------------

type timed struct {
	at time.Time
	ev Event
	// kind names the event for the summary and the labels.
	kind string
}

func (sc *scenario) history(now time.Time) error {
	var evs []timed
	start := now.Add(-23*time.Hour - 30*time.Minute)
	span := 23*time.Hour + 28*time.Minute
	for _, a := range established {
		evs = append(evs, timed{start.Add(-time.Minute), Event{
			Type: "account", AccountID: a.account, IP: a.ip,
			Account: &Account{Action: "login", CreatedAt: stamp(a.created)},
		}, "login"})
		step := span / time.Duration(a.perDay)
		for i := 0; i < a.perDay; i++ {
			at := start.Add(time.Duration(i)*step + time.Duration(sc.rng.Int64N(int64(step))))
			evs = append(evs, timed{at, sc.send(a, i), "send"})
		}
	}
	// The farm: one IP creating an account every few minutes.
	farmStart := now.Add(-8 * time.Hour)
	for i := 1; i <= farmHistory; i++ {
		at := farmStart.Add(time.Duration(i) * 7 * time.Minute)
		evs = append(evs, timed{at, signup(fmt.Sprintf("acct_f%02d", i), farmIP, at), "farm"})
	}
	// New accounts linking through a public shortener. The last one's send
	// is live.
	for i := 1; i <= shortenerNew; i++ {
		acct := fmt.Sprintf("acct_n%02d", i)
		created := now.Add(-time.Duration(2+i*5) * time.Hour)
		evs = append(evs, timed{created, signup(acct, fmt.Sprintf("198.51.100.%d", 100+i), created), "signup"})
		if i < shortenerNew {
			at := created.Add(time.Duration(20+i*7) * time.Minute)
			evs = append(evs, timed{at, sc.shortenerSend(acct, i), "shortener"})
		}
	}
	slices.SortStableFunc(evs, func(a, b timed) int { return a.at.Compare(b.at) })
	for _, t := range evs {
		t.ev.Time = stamp(t.at)
		d, _, err := sc.decide(t.ev, false)
		if err != nil {
			return err
		}
		sc.rec.History[t.kind]++
		sc.collect(d, t.kind)
	}
	sc.rec.History["total"] = len(evs)
	return nil
}

// collect keeps the decision ids the labels need.
func (sc *scenario) collect(d Decision, kind string) {
	for _, m := range append(d.Matches, d.Shadow...) {
		switch m.RuleID {
		case "signup-farm-ip":
			sc.farm = append(sc.farm, d.ID)
		case "shortener-links-new-account":
			sc.shortener = append(sc.shortener, d.ID)
		}
	}
	if kind == "burst" && d.Action == "throttle" {
		sc.throttles = append(sc.throttles, d.ID)
	}
}

func (sc *scenario) recipient() string {
	return fmt.Sprintf("%s.%d@%s", names[sc.rng.IntN(len(names))], 10+sc.rng.IntN(90), domains[sc.rng.IntN(len(domains))])
}

func (sc *scenario) send(a sender, n int) Event {
	return Event{
		Type: "send", AccountID: a.account, APIKeyID: a.key, IP: a.ip,
		From: a.from, To: []string{sc.recipient()}, Subject: fmt.Sprintf(a.subject, 10000+n),
	}
}

func (sc *scenario) shortenerSend(acct string, i int) Event {
	return Event{
		Type: "send", AccountID: acct, APIKeyID: fmt.Sprintf("key_n%02d", i), IP: fmt.Sprintf("198.51.100.%d", 100+i),
		From: fmt.Sprintf("hello@%s.example", strings.TrimPrefix(acct, "acct_")), To: []string{sc.recipient()},
		Subject: "You're invited", Links: []string{fmt.Sprintf("https://bit.ly/3%sQx", strings.ToUpper(acct[5:]))},
	}
}

func signup(acct, ip string, at time.Time) Event {
	return Event{Type: "account", AccountID: acct, IP: ip, Account: &Account{Action: "signup", CreatedAt: stamp(at)}}
}

// --- live ------------------------------------------------------------------

// decide posts ev to /v1/decide (sends) or /v1/events (anything else). Live
// decisions are appended to the lane.
func (sc *scenario) decide(ev Event, live bool) (Decision, *exchange, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return Decision{}, nil, err
	}
	path := "/v1/events"
	if ev.Type == "send" {
		path = "/v1/decide"
	}
	ex, err := sc.s.do(http.MethodPost, path, body, nil)
	if err != nil {
		return Decision{}, ex, err
	}
	return sc.read(ex, ev, live)
}

func (sc *scenario) read(ex *exchange, ev Event, live bool) (Decision, *exchange, error) {
	var resp struct {
		Decision Decision `json:"decision"`
	}
	if err := json.Unmarshal(ex.Response, &resp); err != nil {
		return Decision{}, ex, fmt.Errorf("%s: %w", ex.Path, err)
	}
	d := resp.Decision
	sc.rec.Ruleset = d.Version
	if d.Degraded {
		// Rules that could not be evaluated were skipped; the recording
		// would not show what the ruleset decides.
		return d, ex, fmt.Errorf("decision %s was degraded; run the demo again", d.ID)
	}
	if live {
		sc.seq++
		e := laneEntry{
			Seq: sc.seq, Phase: sc.phase, Type: ev.Type, AccountID: ev.AccountID, APIKeyID: ev.APIKeyID,
			DecisionID: d.ID, Action: d.Action, RetryAfter: d.RetryAfter, LatencyUS: d.LatencyUS,
		}
		if e.Type == "" {
			e.Type = "feedback"
		}
		for _, m := range d.Matches {
			e.Rules = append(e.Rules, m.RuleID)
		}
		for _, m := range d.Shadow {
			e.Shadow = append(e.Shadow, laneMatch{m.RuleID, m.Action})
		}
		sc.rec.Lane = append(sc.rec.Lane, e)
	}
	return d, ex, nil
}

// background sends one email from an established account that is still
// sending.
func (sc *scenario) background(i int) error {
	a := sc.active[i%len(sc.active)]
	sc.counter[a.account]++
	_, _, err := sc.decide(sc.send(a, 20000+sc.counter[a.account]), true)
	return err
}

func (sc *scenario) flow() error {
	sc.phase = "flow"
	order := []int{0, 3, 1, 2, 0, 3, -1, 0, 2, 1, 3, 0}
	for i, who := range order {
		if who < 0 {
			acct := fmt.Sprintf("acct_n%02d", shortenerNew)
			d, ex, err := sc.decide(sc.shortenerSend(acct, shortenerNew), true)
			if err != nil {
				return err
			}
			sc.collect(d, "shortener")
			sc.rec.Steps["flag"] = ex
			continue
		}
		a := established[who]
		sc.counter[a.account]++
		_, ex, err := sc.decide(sc.send(a, 20000+sc.counter[a.account]), true)
		if err != nil {
			return err
		}
		if i == 4 {
			sc.rec.Steps["allow"] = ex
		}
	}
	return nil
}

func (sc *scenario) burst() error {
	sc.phase = "burst"
	created := time.Now().UTC().Truncate(time.Second)
	_, ex, err := sc.decide(signup(burstAccount, burstIP, created), true)
	if err != nil {
		return err
	}
	sc.rec.Steps["burst_signup"] = ex
	for i := 1; i <= burstSends; i++ {
		ev := Event{
			Type: "send", AccountID: burstAccount, APIKeyID: burstKey, IP: burstIP,
			From: "promo@quickdeals.example", To: []string{sc.recipient()}, Subject: "Limited offer: 90% off today only",
		}
		d, ex, err := sc.decide(ev, true)
		if err != nil {
			return err
		}
		sc.collect(d, "burst")
		sc.rec.Burst[d.Action]++
		if d.Action == "throttle" && sc.rec.Steps["throttle"] == nil {
			sc.rec.Steps["throttle"] = ex
			sc.rec.Burst["first_throttle_at"] = i
		}
		if i == 1 {
			sc.rec.Steps["burst_first"] = ex
		}
		if i == 100 {
			sc.rec.Steps["burst_100"] = ex
		}
	}
	return sc.backgrounds(0, 3, 2)
}

func (sc *scenario) complaints() error {
	sc.phase = "complaints"
	fern := established[1]
	for n := 1; n <= 4; n++ {
		fb := Event{
			AccountID: fern.account, From: fern.from,
			Feedback: &Feedback{Kind: "complaint", Recipient: sc.recipient(), MessageID: fmt.Sprintf("msg_fw_%d", 81230+n*17)},
		}
		body, err := json.Marshal(fb)
		if err != nil {
			return err
		}
		sig := signature.Sign(sc.s.feedbackSecret, time.Now(), body)
		ex, err := sc.s.do(http.MethodPost, "/v1/feedback", body, map[string]string{signature.Header: sig})
		if err != nil {
			return err
		}
		if _, _, err := sc.read(ex, fb, true); err != nil {
			return err
		}
		sc.rec.Steps[fmt.Sprintf("complaint_%d", n)] = ex
		if err := sc.background(n % 2 * 2); err != nil { // lumen or tidal
			return err
		}
		sc.counter[fern.account]++
		d, ex, err := sc.decide(sc.send(fern, 20000+sc.counter[fern.account]), true)
		if err != nil {
			return err
		}
		if err := sc.background(3); err != nil { // okapi
			return err
		}
		sc.rec.Complaints = append(sc.rec.Complaints, complaintRound{n, d.Action, d.ID})
		sc.rec.Steps[fmt.Sprintf("complaint_send_%d", n)] = ex
		if d.Action == "hold" && sc.hold == "" {
			sc.hold = d.ID
			sc.rec.Steps["hold"] = ex
		}
	}
	if sc.hold == "" {
		return errors.New("the newsletter account was never held")
	}
	// The platform pauses the held account's campaign until someone looks.
	sc.active = slices.DeleteFunc(sc.active, func(a sender) bool { return a.account == fern.account })
	return sc.backgrounds(0, 1)
}

// backgrounds sends one email from each of the given active accounts.
func (sc *scenario) backgrounds(who ...int) error {
	for _, i := range who {
		if err := sc.background(i); err != nil {
			return err
		}
	}
	return nil
}

func (sc *scenario) leak() error {
	sc.phase = "leak"
	tidal := established[2]
	ev := Event{
		Type: "key_leak", AccountID: tidal.account, APIKeyID: leakedKey,
		Leak: &Leak{Source: "public-repo", URL: "https://code.example/tidal-ops/deploy/blob/main/.env"},
	}
	_, ex, err := sc.decide(ev, true)
	if err != nil {
		return err
	}
	sc.rec.Steps["key_leak"] = ex
	// acct_tidal itself pauses until it has a new key; the others go on.
	if err := sc.backgrounds(0, 2, 0); err != nil {
		return err
	}
	// Someone else uses the key, from their own machine.
	d, ex, err := sc.decide(Event{
		Type: "send", AccountID: tidal.account, APIKeyID: leakedKey, IP: attackerIP,
		From: tidal.from, To: []string{sc.recipient()}, Subject: "Urgent: verify your account",
	}, true)
	if err != nil {
		return err
	}
	if d.Action != "block" {
		return fmt.Errorf("the leaked key was not blocked: %s", d.Action)
	}
	sc.block = d.ID
	sc.rec.Steps["block"] = ex
	if err := sc.backgrounds(2, 0, 2); err != nil {
		return err
	}

	// The platform's receiver gets the signed revoke_key webhook, revokes
	// the key, and the account creates a new one.
	var hook *delivery
	if !waitFor(context.Background(), 10*time.Second, func() bool {
		for _, h := range sc.recv.deliveries() {
			var body struct {
				DecisionID string `json:"decision_id"`
			}
			if json.Unmarshal(h.Body, &body) == nil && body.DecisionID == sc.block {
				hook = &h
				return true
			}
		}
		return false
	}) {
		return errors.New("the revoke_key webhook did not arrive")
	}
	sc.rec.Hook = hook
	log.Printf("hook: %s %s, signature %s", hook.Method, hook.Path, hook.Verified)
	for i := range sc.active {
		if sc.active[i].key == leakedKey {
			sc.active[i].key = rotatedKey
		}
	}
	_, ex, err = sc.decide(Event{
		Type: "account", AccountID: tidal.account, APIKeyID: rotatedKey, IP: tidal.ip,
		Account: &Account{Action: "api_key_created"},
	}, true)
	if err != nil {
		return err
	}
	sc.rec.Steps["key_rotated"] = ex
	return sc.backgrounds(1, 2, 0)
}

func (sc *scenario) shadow() error {
	sc.phase = "shadow"
	for i := farmHistory + 1; i <= farmHistory+3; i++ {
		d, ex, err := sc.decide(signup(fmt.Sprintf("acct_f%02d", i), farmIP, time.Now().UTC().Truncate(time.Second)), true)
		if err != nil {
			return err
		}
		sc.collect(d, "farm")
		sc.rec.Steps["shadow"] = ex
		if i == farmHistory+1 {
			sc.rec.Steps["shadow_first"] = ex
		}
		if err := sc.backgrounds(i, i+1); err != nil {
			return err
		}
	}
	return sc.backgrounds(0, 1, 2, 0, 1)
}

// --- labels and report -----------------------------------------------------

type labelBody struct {
	Verdict string `json:"verdict"`
	By      string `json:"by"`
	Reason  string `json:"reason,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
}

func (sc *scenario) apiLabel(id string, l labelBody) error {
	body, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = sc.s.do(http.MethodPost, "/v1/decisions/"+id+"/labels", body, nil)
	if err == nil {
		sc.rec.Labels[l.Verdict]++
	}
	return err
}

func (sc *scenario) label() error {
	tp, fp := "true_positive", "false_positive"
	if len(sc.farm) != 60 || len(sc.shortener) != shortenerNew || len(sc.throttles) == 0 {
		return fmt.Errorf("unexpected matches: %d farm, %d shortener, %d throttles", len(sc.farm), len(sc.shortener), len(sc.throttles))
	}
	for _, id := range sc.throttles {
		if err := sc.apiLabel(id, labelBody{Verdict: tp, By: "trust@platform.example", Reason: "throwaway signup mailing a bought list"}); err != nil {
			return err
		}
	}
	if err := sc.apiLabel(sc.hold, labelBody{Verdict: tp, By: "deliverability@platform.example", Reason: "list bought last week; complaints confirmed"}); err != nil {
		return err
	}
	if err := sc.apiLabel(sc.block, labelBody{Verdict: tp, By: "security@platform.example", Reason: "key confirmed public in a repository"}); err != nil {
		return err
	}

	// signup-farm-ip, still in shadow: reviewers work through its queue.
	// One verdict is a false positive: a real customer behind the farm's
	// address. The newest match and that one are labeled on the command
	// line, the rest through the API.
	falseFarm := sc.farm[18]
	for _, id := range sc.farm[:len(sc.farm)-1] {
		if id == falseFarm {
			continue
		}
		if err := sc.apiLabel(id, labelBody{Verdict: tp, By: "trust@platform.example", RuleID: "signup-farm-ip", Reason: "throwaway account, never verified"}); err != nil {
			return err
		}
	}
	newest := sc.farm[len(sc.farm)-1]
	c, err := sc.s.cli("label", newest, "--verdict", tp, "--by", "trust@platform.example", "--rule", "signup-farm-ip")
	if err != nil {
		return err
	}
	sc.rec.CLI["label_tp"] = c
	sc.rec.Labels[tp]++
	c, err = sc.s.cli("label", falseFarm, "--verdict", fp, "--by", "support@platform.example", "--rule", "signup-farm-ip",
		"--reason", "real customer behind the same office NAT")
	if err != nil {
		return err
	}
	sc.rec.CLI["label_fp"] = c
	sc.rec.Labels[fp]++

	// shortener-links-new-account, enforced in the demo: appeals reverse
	// most of its flags, and every reversal is a false positive.
	appeals := map[int]string{0: "appeal #4402: webinar invite", 2: "appeal #4407: school newsletter", 3: "appeal #4411: event tickets",
		5: "appeal #4415: podcast launch", 6: "appeal #4418: charity drive", 8: "appeal #4423: product survey"}
	for i, id := range sc.shortener {
		l := labelBody{Verdict: tp, By: "trust@platform.example", Reason: "phishing landing page"}
		if r, ok := appeals[i]; ok {
			l = labelBody{Verdict: fp, By: "support@platform.example", Reason: r}
		}
		if err := sc.apiLabel(id, l); err != nil {
			return err
		}
	}
	return nil
}

func (r *record) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"scenario.json": append(data, '\n'),
		"report.txt":    []byte(r.CLI["report"].Stdout),
		"report.json":   []byte(r.CLI["report_json"].Stdout),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	log.Printf("wrote %s", dir)
	return nil
}
