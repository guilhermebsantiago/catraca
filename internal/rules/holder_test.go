package rules

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeRuleset(t *testing.T, path, threshold string) {
	t.Helper()
	src := "version: 1\nrules:\n  - id: a\n    when: account.sends_1m > " + threshold + "\n    reason: r\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHolder(t *testing.T) {
	var h Holder
	if h.Current() != nil {
		t.Fatal("zero Holder has a ruleset")
	}
	if _, err := h.Reload(); err == nil {
		t.Fatal("Reload with nothing loaded succeeded")
	}

	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRuleset(t, path, "10")
	first, err := h.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if h.Current() != first || h.Path() != path {
		t.Fatalf("Current/Path after Load = %p/%q", h.Current(), h.Path())
	}

	writeRuleset(t, path, "20")
	second, err := h.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if h.Current() != second || second.Version() == first.Version() {
		t.Errorf("Reload did not swap in the edited file: %s -> %s", first.Version(), second.Version())
	}

	// A broken edit keeps the last good ruleset serving.
	if err := os.WriteFile(path, []byte("version: 1\nrules:\n  - id: a\n    when: account.sends_1m >\n    reason: r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Reload(); err == nil {
		t.Fatal("Reload of a broken file succeeded")
	}
	if h.Current() != second {
		t.Error("a failed Reload replaced the current ruleset")
	}

	// A failed Load keeps both the ruleset and the path.
	if _, err := h.Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load of a missing file succeeded")
	}
	if h.Current() != second || h.Path() != path {
		t.Error("a failed Load changed the holder")
	}
}

func TestNewHolderAndStore(t *testing.T) {
	a := mustParse(t, "version: 1\nrules: []\n")
	h := NewHolder(a)
	if h.Current() != a {
		t.Fatal("NewHolder did not store the ruleset")
	}
	b := mustParse(t, designExample)
	h.Store(b)
	if h.Current() != b {
		t.Error("Store did not swap the ruleset")
	}
}

func TestHolderConcurrentReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRuleset(t, path, "10")
	var h Holder
	if _, err := h.Load(path); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				if _, err := h.Reload(); err != nil {
					t.Error(err)
					return
				}
			}
		})
		wg.Go(func() {
			for range 200 {
				if rs := h.Current(); rs == nil || len(rs.Rules()) != 1 {
					t.Error("reader saw a missing or partial ruleset")
					return
				}
			}
		})
	}
	wg.Wait()
}
