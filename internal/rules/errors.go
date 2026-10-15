package rules

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Error is one problem found in a ruleset or fixture file. Line is 1-based
// and 0 when the problem has no position, such as an empty file.
type Error struct {
	File string
	Line int
	// Where names the rule or fixture case the problem is in, for example
	// "rule new-account-burst", when there is one.
	Where string
	Msg   string
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
	if e.Where != "" {
		fmt.Fprintf(&b, "%s: ", e.Where)
	}
	b.WriteString(e.Msg)
	return b.String()
}

// ErrorList is every problem found while loading a file, in file order. Load
// functions return it as their error so a single run reports all mistakes.
type ErrorList []*Error

func (l ErrorList) Error() string {
	msgs := make([]string, len(l))
	for i, e := range l {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "\n")
}

// errs collects errors for one file.
type errs struct {
	file string
	list ErrorList
}

func (c *errs) add(line int, where, format string, args ...any) {
	c.list = append(c.list, &Error{File: c.file, Line: line, Where: where, Msg: fmt.Sprintf(format, args...)})
}

func (c *errs) err() error {
	if len(c.list) == 0 {
		return nil
	}
	slices.SortStableFunc(c.list, func(a, b *Error) int { return a.Line - b.Line })
	return c.list
}

var yamlLineError = regexp.MustCompile(`^yaml: line (\d+): (.*)$`)

// addYAML records a syntax error from the YAML decoder, moving the line
// number it embeds in the message into Error.Line.
func (c *errs) addYAML(err error) {
	msg := err.Error()
	if m := yamlLineError.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		c.add(line, "", "%s", m[2])
		return
	}
	c.add(0, "", "%s", strings.TrimPrefix(msg, "yaml: "))
}

// suggest returns " (did you mean x?)" when one of the candidates is a
// likely typo of name, and "" otherwise.
func suggest(name string, candidates []string) string {
	// Scores are doubled edit distances, so that a candidate that extends
	// name (retry -> retry_after) can beat an equally close one that does not.
	best, bestScore := "", 6
	for _, c := range candidates {
		score := 2 * editDistance(name, c)
		if len(name) >= 3 && strings.HasPrefix(c, name) {
			score = min(score, 1)
		}
		if score < bestScore {
			best, bestScore = c, score
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf(" (did you mean %s?)", best)
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
