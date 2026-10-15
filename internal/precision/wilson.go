// Package precision measures how often each rule is right and decides
// whether it may enforce.
//
// The audit log counts, per rule, how many matches were labeled true or false
// positives. A rule's precision is TP / (TP + FP), but a precision measured on
// a handful of labels says little, so the gate uses the lower bound of the
// Wilson score interval: a rule enforces only when Catraca is 95% confident
// its precision is at least the configured minimum.
package precision

import "math"

// z95 is the standard normal quantile for a two-sided 95% interval.
const z95 = 1.959963984540054

// Wilson returns the Wilson score 95% confidence interval for a proportion
// observed as successes out of trials. With no trials it returns [0, 1]: no
// evidence either way.
func Wilson(successes, trials int) (lower, upper float64) {
	if trials <= 0 {
		return 0, 1
	}
	if successes < 0 {
		successes = 0
	}
	if successes > trials {
		successes = trials
	}
	n := float64(trials)
	p := float64(successes) / n
	z2 := z95 * z95
	denom := 1 + z2/n
	center := p + z2/(2*n)
	margin := z95 * math.Sqrt(p*(1-p)/n+z2/(4*n*n))
	lower = (center - margin) / denom
	upper = (center + margin) / denom
	// Rounding can push the bounds a hair outside [0, 1] at p = 0 or 1.
	return clamp01(lower), clamp01(upper)
}

func clamp01(x float64) float64 {
	return math.Max(0, math.Min(1, x))
}
