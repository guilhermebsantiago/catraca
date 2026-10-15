package config

import (
	"fmt"
	"strings"
)

// LookupFunc returns the value of an environment variable and whether it is
// set, like os.LookupEnv.
type LookupFunc func(name string) (string, bool)

// expand replaces ${NAME} and ${NAME:-default} in s with values from lookup.
//
//   - ${NAME} is the value of NAME. It is an error when NAME is not set, so
//     a missing secret stops the start instead of becoming an empty string.
//   - ${NAME:-default} is the value of NAME, or default when NAME is unset
//     or empty. ${NAME:-} makes a variable optional.
//   - $${ is a literal ${. Any other $ is kept as is, so values such as
//     passwords may contain $ without escaping.
func expand(s string, lookup LookupFunc) (string, error) {
	if !strings.Contains(s, "${") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 2
			continue
		}
		if !strings.HasPrefix(s[i:], "${") {
			b.WriteByte(c)
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated ${ at offset %d (write $${ for a literal ${)", i)
		}
		expr := s[i+2 : i+2+end]
		name, def, hasDef := strings.Cut(expr, ":-")
		if !validVarName(name) {
			return "", fmt.Errorf("${%s}: %q is not a valid environment variable name", expr, name)
		}
		val, set := lookup(name)
		switch {
		case set && val != "":
			b.WriteString(val)
		case hasDef:
			b.WriteString(def)
		case !set:
			return "", fmt.Errorf("environment variable %s is not set (write ${%s:-default} to make it optional)", name, name)
		}
		i += 2 + end
	}
	return b.String(), nil
}

func validVarName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
