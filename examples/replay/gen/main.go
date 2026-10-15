// Command gen writes the synthetic replay dataset in examples/replay: ten
// days of labeled events from a made-up sending platform, mixing legitimate
// senders with abuse, in the JSONL format `catraca replay` reads.
//
// The output is deterministic: the same source writes the same bytes, so the
// committed file can be checked against the generator. Run it from the
// repository root:
//
//	go run ./examples/replay/gen
//
// Everything in it is invented. Sender and company domains use the reserved
// .example and .test TLDs, IP addresses come from the documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32), and
// recipients are random names at real mailbox providers, which is what
// recipient-domain signals look at.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("o", "examples/replay/events.jsonl", "file to write")
	flag.Parse()
	if err := writeFile(*out); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func writeFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := build().write(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
