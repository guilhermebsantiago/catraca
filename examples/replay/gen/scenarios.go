package main

import (
	"fmt"
	"time"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/replay"
)

const (
	legit   = replay.Legit
	abusive = replay.Abusive
)

var (
	transactionalRates = rates{hard: 0.004, soft: 0.006, complaint: 0.0003}
	newsletterRates    = rates{hard: 0.005, soft: 0.01, complaint: 0.0008}
	spamRates          = rates{hard: 0.05, soft: 0.03, complaint: 0.012}
)

// build returns the whole dataset. Each scenario is a function with its own
// random stream; the comments say what each one is there to show.
func build() *dataset {
	d := &dataset{}
	for _, scenario := range []func(*dataset){
		// Legitimate traffic.
		transactional,
		newsletter,
		badCampaign,
		staleList,
		productLaunch,
		serverlessLaunch,
		serverlessSender,
		waitlistLaunch,
		shortenerMarketing,
		eventInvitations,
		ordinarySignups,
		classroomSignups,
		// Abuse.
		leakedKey,
		burstAccounts,
		complaintSpammer,
		boughtList,
		domainSpray,
		phishing,
		takeoverWithProxies,
		takeoverFromOneIP,
		signupFarms,
	} {
		scenario(d)
	}
	return d
}

// transactional: established products sending password resets, receipts
// and reports at a steady pace, from a couple of server IPs each.
func transactional(d *dataset) {
	r := newRNG("transactional")
	brands := []struct {
		name          string
		ageDays, rate int
		tz            int
		b2b           bool
	}{
		{"pagewell", 1400, 40, -3, true},
		{"cartloop", 900, 45, -5, false},
		{"tallyhq", 620, 20, 0, true},
		{"bookbarn", 300, 25, 1, false},
		{"fitlog", 180, 30, -8, false},
		{"ledgerly", 1100, 15, 2, true},
		{"rentnest", 75, 12, -3, false},
		{"shiftly", 460, 18, -4, true},
		{"clinicbee", 40, 10, 5, false},
		{"orbitdesk", 820, 22, 9, true},
	}
	for i, b := range brands {
		s := &sender{
			account:  "acct_" + b.name,
			key:      "key_" + b.name + "_live",
			from:     "no-reply@" + b.name + ".example",
			label:    legit,
			rates:    transactionalRates,
			subjects: transactionalSubjects,
			links:    linksTo("app." + b.name + ".example"),
			to:       oneConsumer,
		}
		ips := []string{fmt.Sprintf("198.51.100.%d", 10+2*i), fmt.Sprintf("198.51.100.%d", 11+2*i)}
		s.ip = fixedIPs(ips...)
		if b.b2b {
			s.to = customerBase(r, 40)
		}
		d.established(s, b.ageDays, "business")
		d.steady(r, s, b.rate, b.tz, start, day(days))
	}
}

// newsletter: a weekly newsletter of 1,050 emails sent in one hour by an
// established account. Its hourly volume is far above its baseline, but it
// comes from the usual IP, so account-takeover-volume leaves it alone, and
// its complaint rate is well below 0.3%.
func newsletter(d *dataset) {
	r := newRNG("newsletter")
	s := &sender{
		account: "acct_brightlane", key: "key_brightlane_live", from: "news@brightlane.example",
		label: legit, rates: newsletterRates, subjects: newsletterSubjects,
		ip: fixedIPs("198.51.100.120"), to: oneConsumer, links: linksTo("brightlane.example"),
	}
	d.established(s, 400, "pro")
	d.steady(r, s, 6, -3, start, day(days))
	d.burst(r, s, 1050, clock(2, 10, 0), time.Hour)
}

// badCampaign: a legitimate newsletter that mails a segment that did not
// want it. Complaints pass 0.3% during the send, so complaint-rate-high
// holds the end of it: a false positive by these labels, since the sender
// is not abusive.
func badCampaign(d *dataset) {
	r := newRNG("bad-campaign")
	s := &sender{
		account: "acct_meadowmail", key: "key_meadowmail_live", from: "updates@meadowmail.example",
		label: legit, rates: newsletterRates, subjects: newsletterSubjects,
		ip: fixedIPs("198.51.100.130"), to: oneConsumer, links: linksTo("meadowmail.example"),
	}
	d.established(s, 200, "pro")
	d.steady(r, s, 4, 0, start, day(days))
	s.rates = rates{hard: 0.012, soft: 0.012, complaint: 0.008}
	d.burst(r, s, 1100, clock(6, 14, 0), time.Hour)
}

// staleList: an old customer re-engaging users who signed up years ago.
// Hard bounces pass 5%, so hard-bounce-rate-high holds the end of the send.
// The hold is arguably useful, but the sender is not abusive: a false
// positive by these labels.
func staleList(d *dataset) {
	r := newRNG("stale-list")
	s := &sender{
		account: "acct_copperkettle", key: "key_copperkettle_live", from: "hello@copperkettle.example",
		label: legit, rates: transactionalRates, subjects: newsletterSubjects,
		ip: fixedIPs("198.51.100.140"), to: oneConsumer, links: linksTo("copperkettle.example"),
	}
	d.established(s, 900, "pro")
	d.steady(r, s, 12, 1, start, day(days))
	s.rates = rates{hard: 0.075, soft: 0.02, complaint: 0.001}
	s.subjects = []string{"We miss you", "It's been a while"}
	d.burst(r, s, 600, clock(8, 9, 0), 2*time.Hour)
}

// productLaunch: an established product announces a release to 320 users in
// 40 minutes, from its usual IPs.
func productLaunch(d *dataset) {
	r := newRNG("product-launch")
	s := &sender{
		account: "acct_northwind", key: "key_northwind_live", from: "team@northwind.example",
		label: legit, rates: transactionalRates, subjects: transactionalSubjects,
		ip: fixedIPs("198.51.100.100", "198.51.100.101"), to: oneConsumer, links: linksTo("northwind.example"),
	}
	d.established(s, 300, "business")
	d.steady(r, s, 20, -5, start, day(days))
	s.subjects, s.rates = launchSubjects, newsletterRates
	d.burst(r, s, 320, clock(8, 14, 0), 40*time.Minute)
}

// serverlessLaunch: an established product moves its mailer to a serverless
// platform on launch day. Every send now comes from a new IP while volume
// spikes, which is exactly what account-takeover-volume and key-many-ips
// look for: false positives.
func serverlessLaunch(d *dataset) {
	r := newRNG("serverless-launch")
	s := &sender{
		account: "acct_sundial", key: "key_sundial_live", from: "hello@sundial.example",
		label: legit, rates: transactionalRates, subjects: transactionalSubjects,
		ip: fixedIPs("198.51.100.110", "198.51.100.111"), to: oneConsumer, links: linksTo("sundial.example"),
	}
	d.established(s, 500, "business")
	migration := clock(7, 15, 0)
	d.steady(r, s, 30, -8, start, migration)
	s.ip = func(r *rng) string { return r.ipv6(0xab) }
	d.steady(r, s, 30, -8, migration, day(days))
	launch := *s
	launch.subjects, launch.rates = launchSubjects, newsletterRates
	d.burst(r, &launch, 300, migration, 40*time.Minute)
}

// serverlessSender: a product that has always sent from a serverless
// platform, so its key is used from many addresses every hour. key-many-ips
// matches it whenever one of those addresses is new to the key.
func serverlessSender(d *dataset) {
	r := newRNG("serverless-sender")
	pool := make([]string, 400)
	for i := range pool {
		pool[i] = r.ipv6(0xaa)
	}
	s := &sender{
		account: "acct_ferrylink", key: "key_ferrylink_live", from: "tickets@ferrylink.example",
		label: legit, rates: transactionalRates, subjects: transactionalSubjects,
		ip: fixedIPs(pool...), to: oneConsumer, links: linksTo("ferrylink.example"),
	}
	d.established(s, 120, "business")
	for n := range days {
		if wd := day(n).Weekday(); wd == time.Saturday || wd == time.Sunday {
			continue
		}
		for h := 14; h < 17; h++ {
			d.burst(r, s, r.between(18, 32), clock(n, h, 0), time.Hour)
		}
	}
}

// waitlistLaunch: a startup signs up, tests, and two hours later announces
// itself to a waitlist of 220 people, in about a minute and a half.
// new-account-burst throttles it: a false positive.
func waitlistLaunch(d *dataset) {
	r := newRNG("waitlist-launch")
	signup := clock(1, 9, 0)
	s := &sender{
		account: "acct_loopwise", key: "key_loopwise_live", from: "hello@loopwise.example",
		label: legit, rates: newsletterRates, subjects: []string{"Testing", "Hello from Loopwise"},
		ip: fixedIPs("198.51.100.90"), links: linksTo("loopwise.example"),
		to: func(r *rng) []string { return []string{r.person() + "@loopwise.example"} },
	}
	d.accountEvent(signup, s.account, "192.0.2.10", "signup", "free", signup, legit)
	d.burst(r, s, 6, signup.Add(20*time.Minute), 40*time.Minute)
	s.to, s.subjects = oneConsumer, []string{"Loopwise is live: you're in"}
	d.burst(r, s, 220, clock(1, 11, 0), 95*time.Second)
	s.subjects = transactionalSubjects
	d.steady(r, s, 20, -3, day(2), day(days))
}

// shortenerMarketing: a new shop links its first campaigns through bit.ly,
// as marketing tools often do. shortener-links-new-account flags it while
// the account is under three days old: false positives.
func shortenerMarketing(d *dataset) {
	r := newRNG("shortener-marketing")
	signup := clock(3, 16, 0)
	s := &sender{
		account: "acct_petalbox", key: "key_petalbox_live", from: "shop@petalbox.example",
		label: legit, rates: newsletterRates, subjects: []string{"New arrivals this week", "Our autumn collection"},
		ip: fixedIPs("198.51.100.150"), to: oneConsumer,
		links: func(r *rng) []string {
			return []string{"https://bit.ly/" + r.token(7), "https://petalbox.example/shop"}
		},
	}
	d.accountEvent(signup, s.account, "192.0.2.44", "signup", "free", signup, legit)
	for _, at := range []time.Time{clock(3, 17, 0), clock(4, 10, 0), clock(5, 10, 0), clock(6, 18, 0)} {
		d.burst(r, s, 15, at, 30*time.Minute)
	}
}

// eventInvitations: a new events company invites 360 people at 300 or so
// companies in under an hour. recipient-domain-spray holds the end of it:
// false positives.
func eventInvitations(d *dataset) {
	r := newRNG("event-invitations")
	signup := clock(6, 8, 30)
	s := &sender{
		account: "acct_summitly", key: "key_summitly_live", from: "invites@summitly.example",
		label: legit, rates: transactionalRates, subjects: []string{"Welcome to Summitly"},
		ip: fixedIPs("198.51.100.160"), to: oneConsumer, links: linksTo("summitly.example"),
	}
	d.accountEvent(signup, s.account, "192.0.2.58", "signup", "pro", signup, legit)
	d.burst(r, s, 4, signup.Add(time.Hour), 2*time.Hour)
	s.subjects = []string{"You're invited: Fintech Summit 2026"}
	s.to = func(r *rng) []string {
		to := make([]string, r.between(5, 7))
		for i := range to {
			to[i] = r.person() + "@" + pick(r, companies)
		}
		return to
	}
	d.burst(r, s, 60, clock(8, 10, 0), 50*time.Minute)
}

// ordinarySignups: new customers who sign up and start sending a little.
// Some never send.
func ordinarySignups(d *dataset) {
	r := newRNG("ordinary-signups")
	for i := range 22 {
		signup := start.Add(time.Duration(r.intn(days*24)) * time.Hour).Add(r.within(time.Hour))
		name := fmt.Sprintf("newuser%02d", i+1)
		ip := fmt.Sprintf("192.0.2.%d", 100+i)
		if r.chance(0.4) {
			ip = r.ipv6(0x100 + uint16(i))
		}
		s := &sender{
			account: "acct_" + name, key: "key_" + name, from: "me@" + name + ".example",
			label: legit, rates: transactionalRates, subjects: transactionalSubjects,
			ip: fixedIPs(ip), to: oneConsumer, links: linksTo(name + ".example"),
		}
		if r.chance(0.5) {
			s.links = noLinks
		}
		d.accountEvent(signup, s.account, ip, "signup", pick(r, []string{"free", "free", "pro"}), signup, legit)
		if r.chance(0.3) {
			continue
		}
		d.burst(r, s, r.between(1, 3), signup.Add(10*time.Minute), time.Hour)
		d.steady(r, s, r.between(3, 15), r.between(-8, 3), signup.Add(2*time.Hour), day(days))
	}
}

// classroomSignups: a class signs up from the campus network, which puts
// everyone behind one address. signup-farm-ip flags the fifth signup on:
// false positives.
func classroomSignups(d *dataset) {
	r := newRNG("classroom-signups")
	for i := range 7 {
		at := clock(8, 14, 0).Add(time.Duration(i)*20*time.Minute + r.within(10*time.Minute))
		name := fmt.Sprintf("student%02d", i+1)
		s := &sender{
			account: "acct_" + name, key: "key_" + name, from: name + "@uni-campus.example",
			label: legit, rates: transactionalRates, subjects: []string{"Test", "Assignment 2"},
			ip: fixedIPs("192.0.2.77"), links: noLinks,
			to: func(r *rng) []string { return []string{r.person() + "@uni-campus.example"} },
		}
		d.accountEvent(at, s.account, "192.0.2.77", "signup", "free", at, legit)
		d.burst(r, s, r.between(2, 4), at.Add(5*time.Minute), 40*time.Minute)
	}
}

// leakedKey: a customer's key is pushed to a public repository. Abusers send
// with it from 45 proxy addresses for over an hour; then GitHub reports the
// leak, leaked-key-send blocks what follows, and the customer rotates the
// key. Most abusive sends before the report are missed: key-many-ips only
// matches a send from an address new to the key, so once an address has
// sent, its next sends go through.
func leakedKey(d *dataset) {
	r := newRNG("leaked-key")
	owner := &sender{
		account: "acct_tidepool", key: "key_tidepool_live", from: "no-reply@tidepool.example",
		label: legit, rates: transactionalRates, subjects: transactionalSubjects,
		ip: fixedIPs("198.51.100.40"), to: oneConsumer, links: linksTo("app.tidepool.example"),
	}
	d.established(owner, 250, "business")
	report, rotated := clock(5, 11, 40), clock(5, 12, 5)
	d.steady(r, owner, 30, -4, start, report)

	proxies := make([]string, 45)
	for i := range proxies {
		proxies[i] = r.ipv6(0x77)
	}
	abuser := &sender{
		account: owner.account, key: owner.key, from: "billing@tidepool.example",
		label: abusive, rates: spamRates, subjects: spamSubjects,
		ip: fixedIPs(proxies...), to: oneConsumer, links: shortLinks,
	}
	d.burst(r, abuser, 260, clock(5, 10, 25), 75*time.Minute)
	d.add(event.Event{
		Type: event.KeyLeak, Time: report, AccountID: owner.account, APIKeyID: owner.key,
		Leak: &event.LeakInfo{Source: "github", URL: "https://github.com/example/demo-app/blob/main/.env"},
	}, replay.Unlabeled)
	abuser.blocked = true
	d.burst(r, abuser, 60, report.Add(time.Second), 20*time.Minute)

	owner.key = "key_tidepool_live_2"
	d.accountEvent(rotated, owner.account, "198.51.100.40", "api_key_created", "business", start.AddDate(0, 0, -250), legit)
	d.steady(r, owner, 30, -4, rotated, day(days))
}

// burstAccounts: throwaway accounts that sign up and blast a few hundred
// emails within minutes. new-account-burst catches each blast once it
// passes 100 sends in a minute.
func burstAccounts(d *dataset) {
	r := newRNG("burst-accounts")
	for i, signup := range []time.Time{clock(1, 3, 12), clock(4, 22, 5), clock(8, 13, 30)} {
		ip := fmt.Sprintf("203.0.113.%d", 11+i)
		s := &sender{
			account: fmt.Sprintf("acct_burst%02d", i+1), key: fmt.Sprintf("key_burst%02d", i+1),
			from: fmt.Sprintf("offers@deals-%02d.test", i+1), label: abusive, rates: spamRates,
			subjects: spamSubjects, ip: fixedIPs(ip), to: oneConsumer, links: linksTo("promo-hub.test"),
		}
		d.accountEvent(signup, s.account, ip, "signup", "free", signup, abusive)
		n := r.between(220, 320)
		d.burst(r, s, n, signup.Add(time.Duration(r.between(5, 20))*time.Minute), time.Duration(n)*time.Minute/200)
	}
}

// complaintSpammer: an account that warms up for a few days, then mails a
// purchased list. complaint-rate-high holds it once it has 1,000 sends in
// the window.
func complaintSpammer(d *dataset) {
	r := newRNG("complaint-spammer")
	s := &sender{
		account: "acct_megapromo", key: "key_megapromo", from: "news@megapromo.test",
		label: abusive, rates: newsletterRates, subjects: spamSubjects,
		ip: fixedIPs("203.0.113.30"), to: oneConsumer, links: linksTo("megapromo.test"),
	}
	d.established(s, 9, "pro")
	d.steady(r, s, 10, 0, start, day(3))
	s.rates = rates{hard: 0.035, soft: 0.03, complaint: 0.02}
	d.burst(r, s, 1250, clock(3, 13, 0), 3*time.Hour)
}

// boughtList: an account mails a bought list, full of addresses that do not
// exist. hard-bounce-rate-high holds it after 500 sends.
func boughtList(d *dataset) {
	r := newRNG("bought-list")
	s := &sender{
		account: "acct_leadstorm", key: "key_leadstorm", from: "sales@leadstorm.test",
		label: abusive, rates: newsletterRates, subjects: b2bSpamSubjects,
		ip: fixedIPs("203.0.113.40"), to: oneConsumer, links: linksTo("leadstorm.test"),
	}
	d.established(s, 20, "pro")
	d.steady(r, s, 5, 0, start, day(5))
	s.rates = rates{hard: 0.14, soft: 0.03, complaint: 0.0025}
	d.burst(r, s, 700, clock(5, 10, 0), 150*time.Minute)
}

// domainSpray: new accounts mailing addresses scraped from company
// websites, a few hundred companies an hour. recipient-domain-spray holds
// them once they pass 200 recipients in the hour.
func domainSpray(d *dataset) {
	r := newRNG("domain-spray")
	for i, signup := range []time.Time{clock(1, 19, 40), clock(6, 7, 10)} {
		ip := fmt.Sprintf("203.0.113.%d", 21+i)
		s := &sender{
			account: fmt.Sprintf("acct_spray%02d", i+1), key: fmt.Sprintf("key_spray%02d", i+1),
			from: fmt.Sprintf("growth@b2b-leads-%02d.test", i+1), label: abusive,
			rates: rates{hard: 0.08, soft: 0.03, complaint: 0.004}, subjects: b2bSpamSubjects,
			ip: fixedIPs(ip), to: scraped(6, 12), links: linksTo("b2b-leads.test"),
		}
		d.accountEvent(signup, s.account, ip, "signup", "free", signup, abusive)
		d.burst(r, s, 50, signup.Add(50*time.Minute), time.Hour)
	}
}

// phishing: new accounts sending credential phishing through URL
// shorteners, which shortener-links-new-account flags. The last one links
// to a lookalike domain instead and is missed.
func phishing(d *dataset) {
	r := newRNG("phishing")
	for i, signup := range []time.Time{clock(2, 6, 0), clock(4, 15, 0), clock(6, 18, 20), clock(9, 5, 0)} {
		ip := fmt.Sprintf("203.0.113.%d", 31+i)
		s := &sender{
			account: fmt.Sprintf("acct_phish%02d", i+1), key: fmt.Sprintf("key_phish%02d", i+1),
			from: fmt.Sprintf("security@account-alerts-%02d.test", i+1), label: abusive,
			rates: rates{hard: 0.03, soft: 0.02, complaint: 0.015}, subjects: phishSubjects,
			ip: fixedIPs(ip), to: oneConsumer, links: shortLinks,
		}
		if i == 3 {
			s.links = linksTo("secure-login-verify.example")
		}
		d.accountEvent(signup, s.account, ip, "signup", "free", signup, abusive)
		d.burst(r, s, r.between(30, 60), signup.Add(30*time.Minute), time.Duration(r.between(2, 5))*time.Hour)
	}
}

// takeoverWithProxies: an attacker takes over an old account at night,
// creates a key and sends 500 emails in 45 minutes through residential
// proxies, a new address for nearly every send. account-takeover-volume
// holds it once the hour passes 200 sends.
func takeoverWithProxies(d *dataset) {
	r := newRNG("takeover-proxies")
	owner := &sender{
		account: "acct_harborcafe", key: "key_harborcafe_live", from: "hello@harborcafe.example",
		label: legit, rates: transactionalRates, subjects: transactionalSubjects,
		ip: fixedIPs("198.51.100.70", "198.51.100.71"), to: customerBase(r, 30), links: linksTo("harborcafe.example"),
	}
	d.established(owner, 700, "pro")
	d.steady(r, owner, 25, -5, start, day(days))

	login := clock(7, 2, 10)
	created := start.AddDate(0, 0, -700)
	d.accountEvent(login, owner.account, r.ipv6(0x88), "login", "pro", created, abusive)
	d.accountEvent(login.Add(2*time.Minute), owner.account, r.ipv6(0x88), "api_key_created", "pro", created, abusive)
	attacker := &sender{
		account: owner.account, key: "key_harborcafe_2", from: "hello@harborcafe.example",
		label: abusive, rates: spamRates, subjects: phishSubjects,
		ip: func(r *rng) string { return r.ipv6(0x88) }, to: oneConsumer, links: shortLinks,
	}
	d.burst(r, attacker, 500, login.Add(5*time.Minute), 45*time.Minute)
}

// takeoverFromOneIP: the same attack from a single server. Only the first
// send comes from an address new to the account, and the hour has one send
// then, so account-takeover-volume misses every send: a gap in the rule,
// left in so the numbers show it.
func takeoverFromOneIP(d *dataset) {
	r := newRNG("takeover-one-ip")
	owner := &sender{
		account: "acct_quillpress", key: "key_quillpress_live", from: "news@quillpress.example",
		label: legit, rates: transactionalRates, subjects: newsletterSubjects,
		ip: fixedIPs("198.51.100.80"), to: oneConsumer, links: linksTo("quillpress.example"),
	}
	d.established(owner, 1000, "pro")
	d.steady(r, owner, 15, 1, start, day(days))

	login := clock(9, 22, 0)
	d.accountEvent(login, owner.account, "203.0.113.200", "login", "pro", start.AddDate(0, 0, -1000), abusive)
	attacker := *owner
	attacker.label, attacker.rates, attacker.subjects = abusive, spamRates, spamSubjects
	attacker.ip, attacker.links = fixedIPs("203.0.113.200"), shortLinks
	d.burst(r, &attacker, 350, login.Add(3*time.Minute), 40*time.Minute)
}

// signupFarms: one address creating a dozen accounts in a few hours, each
// sending a handful of shortened links. signup-farm-ip flags signups from
// the fifth on; shortener-links-new-account flags the sends.
func signupFarms(d *dataset) {
	r := newRNG("signup-farms")
	farms := []struct {
		ip       string
		from     time.Time
		accounts int
		span     time.Duration
	}{
		{"203.0.113.66", clock(3, 9, 0), 12, 4 * time.Hour},
		{"203.0.113.67", clock(9, 1, 0), 9, 2 * time.Hour},
	}
	n := 0
	for _, f := range farms {
		step := f.span / time.Duration(f.accounts)
		for i := range f.accounts {
			n++
			at := f.from.Add(time.Duration(i)*step + r.within(step))
			s := &sender{
				account: fmt.Sprintf("acct_farm%02d", n), key: fmt.Sprintf("key_farm%02d", n),
				from: fmt.Sprintf("noreply@farm%02d.test", n), label: abusive, rates: spamRates,
				subjects: spamSubjects, ip: fixedIPs(f.ip), to: oneConsumer, links: shortLinks,
			}
			d.accountEvent(at, s.account, f.ip, "signup", "free", at, abusive)
			d.burst(r, s, r.between(3, 8), at.Add(time.Duration(r.between(10, 60))*time.Minute), 30*time.Minute)
		}
	}
}
