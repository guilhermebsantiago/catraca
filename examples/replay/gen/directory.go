package main

import (
	"fmt"
	"strings"
)

// providers are mailbox providers weighted roughly by their share of a
// consumer list in the Americas and Europe.
var providers = []weighted[string]{
	{"gmail.com", 40}, {"outlook.com", 9}, {"hotmail.com", 7}, {"yahoo.com", 9},
	{"icloud.com", 7}, {"live.com", 3}, {"aol.com", 2}, {"proton.me", 2},
	{"gmx.de", 2}, {"web.de", 1}, {"orange.fr", 2}, {"free.fr", 1},
	{"libero.it", 1}, {"comcast.net", 2}, {"uol.com.br", 3}, {"bol.com.br", 2},
	{"terra.com.br", 1}, {"yahoo.com.br", 3}, {"hotmail.com.br", 2},
}

var firstNames = strings.Fields(`ana bruno carla diego elena felipe gabriela hugo ines joao
karen lucas maria nina otavio paula rafael sofia tiago vera william yara alex
ben chloe daniel emma finn grace harry isla jack kate leo mia noah olivia sam
tom lena marco priya kenji amara`)

var lastNames = strings.Fields(`silva souza costa lima alves rocha gomes ribeiro martins
carvalho smith jones brown taylor wilson davies evans thomas roberts walker
muller schmidt garcia lopez rossi dubois nakamura okafor patel novak`)

var companyHeads = strings.Fields(`acme blue bright cedar delta ember fern granite harbor
iron jade kite lumen maple north oak pine quartz river summit terra umber vale
willow zephyr apex birch coral dune echo`)

var companyTails = strings.Fields(`labs works soft data cloud health foods logistics
studio capital tech systems media retail energy legal travel learning finance
motors`)

// companies are made-up company domains under reserved TLDs.
var companies = func() []string {
	var out []string
	for _, tld := range []string{"example", "test"} {
		for _, h := range companyHeads {
			for _, t := range companyTails {
				out = append(out, h+t+"."+tld)
			}
		}
	}
	return out
}()

func (r *rng) person() string {
	return pick(r, firstNames) + "." + pick(r, lastNames)
}

// consumer returns an address at a mailbox provider.
func (r *rng) consumer() string {
	return fmt.Sprintf("%s%d@%s", r.person(), r.intn(100), pickWeighted(r, providers))
}

// customerBase returns a recipient picker for a B2B product: people at a
// fixed set of client companies, plus some at mailbox providers.
func customerBase(r *rng, clients int) func(r *rng) []string {
	domains := make([]string, clients)
	for i := range domains {
		domains[i] = pick(r, companies)
	}
	return func(r *rng) []string {
		if r.chance(0.2) {
			return []string{r.consumer()}
		}
		return []string{r.person() + "@" + pick(r, domains)}
	}
}

func oneConsumer(r *rng) []string { return []string{r.consumer()} }

// scraped returns between lo and hi role addresses at random companies: a
// list scraped from company websites.
func scraped(lo, hi int) func(r *rng) []string {
	roles := strings.Fields("info contact sales hello admin office support marketing hr")
	return func(r *rng) []string {
		to := make([]string, r.between(lo, hi))
		for i := range to {
			to[i] = pick(r, roles) + "@" + pick(r, companies)
		}
		return to
	}
}

var shorteners = strings.Fields("bit.ly tinyurl.com cutt.ly is.gd rb.gy")

// shortLinks returns a link through a public URL shortener.
func shortLinks(r *rng) []string {
	return []string{"https://" + pick(r, shorteners) + "/" + r.token(7)}
}

var (
	transactionalSubjects = []string{
		"Reset your password", "Your receipt", "Verify your email address",
		"New sign-in to your account", "Your order has shipped",
		"Your invoice is ready", "Your weekly report", "Confirm your subscription",
	}
	newsletterSubjects = []string{
		"This week's highlights", "New in September", "Your monthly digest",
		"Five ideas for your weekend", "What's new this month",
	}
	launchSubjects = []string{
		"Introducing our biggest release yet", "It's here: the new app",
		"You're invited to try the new version",
	}
	spamSubjects = []string{
		"Exclusive deal just for you", "You have (1) unclaimed reward",
		"Limited time: 90% off today only", "Your package could not be delivered",
		"Congratulations, you have been selected",
	}
	phishSubjects = []string{
		"Action required: verify your account", "Unusual sign-in activity",
		"Your mailbox is almost full", "Payment failed: update your billing details",
	}
	b2bSpamSubjects = []string{
		"Quick question about your website", "Grow your sales by 300%",
		"Partnership opportunity", "Cheap SEO services for your business",
	}
)
