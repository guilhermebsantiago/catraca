package config

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
)

// Error is one problem found in a configuration file. Line is 1-based and 0
// when the problem has no position, such as a required field left out of an
// empty file.
type Error struct {
	File string
	Line int
	// Path is the field the problem is about, for example
	// "store.redis.url" or "hooks[0].secret". It is empty for problems with
	// the file as a whole.
	Path string
	Msg  string
}

func (e *Error) Error() string {
	var b strings.Builder
	switch {
	case e.File != "" && e.Line > 0:
		fmt.Fprintf(&b, "%s:%d: ", e.File, e.Line)
	case e.File != "":
		fmt.Fprintf(&b, "%s: ", e.File)
	case e.Line > 0:
		fmt.Fprintf(&b, "line %d: ", e.Line)
	}
	if e.Path != "" {
		fmt.Fprintf(&b, "%s: ", e.Path)
	}
	b.WriteString(e.Msg)
	return b.String()
}

// ErrorList is every problem found in a configuration file, in file order.
// Load and Parse return it so that one run reports every mistake.
type ErrorList []*Error

func (l ErrorList) Error() string {
	msgs := make([]string, len(l))
	for i, e := range l {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "\n")
}

// sorted orders the list by line, keeping the order of problems on one line.
// Problems without a line, such as a required section left out, come last.
func (l ErrorList) sorted() ErrorList {
	key := func(e *Error) int {
		if e.Line == 0 {
			return math.MaxInt
		}
		return e.Line
	}
	slices.SortStableFunc(l, func(a, b *Error) int { return cmp.Compare(key(a), key(b)) })
	return l
}

// suggest returns " (did you mean x?)" when one of the candidates is a likely
// typo of name, and "" otherwise.
func suggest(name string, candidates []string) string {
	if best := closest(name, candidates); best != "" {
		return fmt.Sprintf(" (did you mean %s?)", best)
	}
	return ""
}

// closest returns the candidate name is most likely a typo of, or "".
func closest(name string, candidates []string) string {
	best, bestDist := "", 3
	for _, c := range candidates {
		d := editDistance(name, c)
		if len(name) >= 3 && strings.HasPrefix(c, name) {
			d = min(d, 1)
		}
		if d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
