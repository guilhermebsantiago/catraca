package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// The configuration is decoded by walking the yaml.Node tree against the
// Config struct instead of with yaml.Unmarshal. That is what turns unknown
// and repeated fields into errors with line numbers and suggestions, expands
// environment variables in values only (a secret full of YAML syntax stays a
// plain string), and reports every mistake in one run.

// decoder decodes one file.
type decoder struct {
	file   string
	lookup LookupFunc
	errs   ErrorList
	// lines maps every field present in the file to the line of its value,
	// so validation can point at the line it complains about.
	lines map[string]int
	// bad holds the fields that failed to decode, so validation does not
	// report a second, misleading problem for them.
	bad map[string]bool
}

func (d *decoder) add(line int, path, format string, args ...any) {
	d.errs = append(d.errs, &Error{File: d.file, Line: line, Path: path, Msg: fmt.Sprintf(format, args...)})
	d.bad[path] = true
}

var yamlLineError = regexp.MustCompile(`^yaml: line (\d+): (.*)$`)

// document parses data and decodes its root mapping into v. It reports
// false when the file is not a YAML mapping at all, in which case there is
// nothing to validate.
func (d *decoder) document(data []byte, v any) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		msg := err.Error()
		if m := yamlLineError.FindStringSubmatch(msg); m != nil {
			line, _ := strconv.Atoi(m[1])
			d.add(line, "", "%s", m[2])
			return false
		}
		d.add(0, "", "%s", strings.TrimPrefix(msg, "yaml: "))
		return false
	}
	if len(doc.Content) == 0 {
		return true // an empty file: every field takes its default
	}
	root := resolve(doc.Content[0])
	if isNull(root) {
		return true
	}
	if root.Kind != yaml.MappingNode {
		d.add(root.Line, "", "the configuration must be a mapping of settings")
		return false
	}
	d.value(root, reflect.ValueOf(v).Elem(), "")
	return true
}

var durationType = reflect.TypeFor[time.Duration]()

func (d *decoder) value(n *yaml.Node, v reflect.Value, path string) {
	n = resolve(n)
	if path != "" {
		d.lines[path] = n.Line
	}
	if v.Kind() == reflect.Pointer {
		// A section that is present, even empty or null, is enabled.
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if isNull(n) {
			return
		}
		d.value(n, v.Elem(), path)
		return
	}
	if isNull(n) {
		return
	}
	switch {
	case v.Type() == durationType:
		s, ok := d.scalar(n, path, "a duration")
		if !ok {
			return
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			d.add(n.Line, path, "want a duration such as 10ms, 30s or 2h, got %q", s)
			return
		}
		v.SetInt(int64(dur))
	case v.Kind() == reflect.Struct:
		d.structure(n, v, path)
	case v.Kind() == reflect.Slice:
		d.sequence(n, v, path)
	case v.Kind() == reflect.Map:
		d.stringMap(n, v, path)
	case v.Kind() == reflect.String:
		if s, ok := d.scalar(n, path, "a string"); ok {
			v.SetString(s)
		}
	case v.Kind() == reflect.Bool:
		s, ok := d.scalar(n, path, "true or false")
		if !ok {
			return
		}
		switch strings.ToLower(s) {
		case "true":
			v.SetBool(true)
		case "false":
			v.SetBool(false)
		default:
			d.add(n.Line, path, "want true or false, got %q", s)
		}
	case v.CanInt():
		s, ok := d.scalar(n, path, "an integer")
		if !ok {
			return
		}
		i, err := strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 10, 64)
		if err != nil || v.OverflowInt(i) {
			d.add(n.Line, path, "want an integer, got %q", s)
			return
		}
		v.SetInt(i)
	case v.CanFloat():
		s, ok := d.scalar(n, path, "a number")
		if !ok {
			return
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			d.add(n.Line, path, "want a number, got %q", s)
			return
		}
		v.SetFloat(f)
	default:
		panic(fmt.Sprintf("config: field %s has unsupported type %s", path, v.Type()))
	}
}

// scalar returns the text of a scalar node with environment variables
// expanded. want describes the expected value for the error message.
func (d *decoder) scalar(n *yaml.Node, path, want string) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		d.add(n.Line, path, "want %s, got %s", want, kindName(n))
		return "", false
	}
	s, err := expand(n.Value, d.lookup)
	if err != nil {
		d.add(n.Line, path, "%s", err)
		return "", false
	}
	return s, true
}

func (d *decoder) structure(n *yaml.Node, v reflect.Value, path string) {
	if n.Kind != yaml.MappingNode {
		d.add(n.Line, path, "want a mapping of settings, got %s", kindName(n))
		return
	}
	fields := yamlFields(v.Type())
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	seen := map[string]bool{}
	d.pairs(n, path, func(key string, k, val *yaml.Node) {
		child := join(path, key)
		idx, ok := fields[key]
		switch {
		case !ok:
			d.add(k.Line, child, "unknown field%s", suggest(key, names))
			// A misspelled field is reported once, not again as a
			// required field that is missing.
			if like := closest(key, names); like != "" {
				d.bad[join(path, like)] = true
			}
		case seen[key]:
			d.add(k.Line, child, "set twice")
		default:
			seen[key] = true
			d.value(val, v.Field(idx), child)
		}
	})
}

func (d *decoder) sequence(n *yaml.Node, v reflect.Value, path string) {
	if n.Kind != yaml.SequenceNode {
		d.add(n.Line, path, "want a list, got %s", kindName(n))
		return
	}
	s := reflect.MakeSlice(v.Type(), len(n.Content), len(n.Content))
	for i, item := range n.Content {
		d.value(item, s.Index(i), fmt.Sprintf("%s[%d]", path, i))
	}
	v.Set(s)
}

func (d *decoder) stringMap(n *yaml.Node, v reflect.Value, path string) {
	if n.Kind != yaml.MappingNode {
		d.add(n.Line, path, "want a mapping, got %s", kindName(n))
		return
	}
	m := reflect.MakeMapWithSize(v.Type(), len(n.Content)/2)
	d.pairs(n, path, func(key string, k, val *yaml.Node) {
		child := join(path, key)
		if m.MapIndex(reflect.ValueOf(key)).IsValid() {
			d.add(k.Line, child, "set twice")
			return
		}
		elem := reflect.New(v.Type().Elem()).Elem()
		d.value(val, elem, child)
		m.SetMapIndex(reflect.ValueOf(key).Convert(v.Type().Key()), elem)
	})
	v.Set(m)
}

// pairs calls fn for each key of a mapping, rejecting keys that are not plain
// strings and YAML merge keys.
func (d *decoder) pairs(n *yaml.Node, path string, fn func(key string, k, v *yaml.Node)) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := resolve(n.Content[i]), n.Content[i+1]
		switch {
		case k.Kind != yaml.ScalarNode:
			d.add(k.Line, path, "keys must be plain strings")
		case k.Value == "<<":
			d.add(k.Line, path, "YAML merge keys (<<) are not supported")
		default:
			fn(k.Value, k, v)
		}
	}
}

// yamlFields maps the yaml names of a struct's fields to their indexes.
func yamlFields(t reflect.Type) map[string]int {
	out := make(map[string]int, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = i
	}
	return out
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// resolve follows YAML aliases (*name) to the node they point at.
func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		return fmt.Sprintf("%q", n.Value)
	}
	return "an unsupported value"
}
