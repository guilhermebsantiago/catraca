package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func generate(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := build().write(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestCommittedDatasetIsCurrent fails when events.jsonl and the generator
// disagree, so a change to a scenario comes with the data it produces.
func TestCommittedDatasetIsCurrent(t *testing.T) {
	want := generate(t)
	got, err := os.ReadFile(filepath.Join("..", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("examples/replay/events.jsonl is not what the generator writes (%d bytes, want %d); "+
			"run `go run ./examples/replay/gen` from the repository root and commit the result", len(got), len(want))
	}
}

func TestGeneratorIsDeterministic(t *testing.T) {
	if !bytes.Equal(generate(t), generate(t)) {
		t.Fatal("two runs of the generator wrote different data")
	}
}

func TestWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := writeFile(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, generate(t)) {
		t.Error("writeFile wrote something other than the generator's output")
	}
	if err := writeFile(filepath.Join(t.TempDir(), "missing", "events.jsonl")); err == nil {
		t.Error("writeFile into a missing directory succeeded")
	}
}
