package rules

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"
	"go.yaml.in/yaml/v3"

	"github.com/guilhermebsantiago/catraca/internal/event"
	"github.com/guilhermebsantiago/catraca/internal/signal"
)

// MaxCost is the CEL runtime cost a rule with a comprehension (all, exists,
// exists_one, map, filter) may spend on one evaluation; past it the rule
// fails to evaluate and follows on_error. It keeps nested loops over large
// lists from eating the decision's latency budget. Comparisons and lookups
// cost about one unit each, so even a loop over hundreds of recipient domains
// fits.
//
// Rules without comprehensions evaluate each node once, in time linear in the
// expression and its inputs, so they skip runtime cost tracking, which would
// make them several times slower.
const MaxCost = 10_000

// variables are the names rules read signals from, in signal.Set order.
var variables = []string{"event", "account", "key", "ip", "domain", "entity"}

// newEnv builds the CEL environment for a ruleset. Lists are bound into the
// in_list and any_in_list functions, so each ruleset gets its own env.
func newEnv(lists map[string][]string) (*cel.Env, error) {
	sets := make(map[string]map[string]struct{}, len(lists))
	for name, items := range lists {
		set := make(map[string]struct{}, len(items))
		for _, item := range items {
			set[item] = struct{}{}
		}
		sets[name] = set
	}
	inList := func(name, value ref.Val) ref.Val {
		set := sets[string(name.(types.String))]
		s, ok := value.(types.String)
		if !ok {
			return types.NewErr("in_list: value must be a string, not %s", value.Type().TypeName())
		}
		_, found := set[string(s)]
		return types.Bool(found)
	}
	anyInList := func(name, values ref.Val) ref.Val {
		set := sets[string(name.(types.String))]
		l, ok := values.(traits.Lister)
		if !ok {
			return types.NewErr("any_in_list: second argument must be a list, not %s", values.Type().TypeName())
		}
		for it := l.Iterator(); it.HasNext() == types.True; {
			v := it.Next()
			s, ok := v.(types.String)
			if !ok {
				return types.NewErr("any_in_list: list items must be strings, not %s", v.Type().TypeName())
			}
			if _, found := set[string(s)]; found {
				return types.True
			}
		}
		return types.False
	}
	domainOf := func(address ref.Val) ref.Val {
		return types.String(event.DomainOf(string(address.(types.String))))
	}
	ratio := func(a, b ref.Val) ref.Val {
		x, err := toFloat(a)
		if err != nil {
			return types.NewErr("ratio: %v", err)
		}
		y, err := toFloat(b)
		if err != nil {
			return types.NewErr("ratio: %v", err)
		}
		return types.Double(x / math.Max(y, 1))
	}

	signals := cel.MapType(cel.StringType, cel.DynType)
	opts := make([]cel.EnvOption, 0, len(variables)+6)
	for _, name := range variables {
		opts = append(opts, cel.Variable(name, signals))
	}
	opts = append(opts,
		// Counts are ints and rates are doubles, so `account.age_hours < 24`
		// must work without a cast.
		cel.CrossTypeNumericComparisons(true),
		cel.OptionalTypes(),
		cel.Function("in_list",
			cel.Overload("in_list_string_dyn", []*cel.Type{cel.StringType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(inList))),
		cel.Function("any_in_list",
			cel.Overload("any_in_list_string_list", []*cel.Type{cel.StringType, cel.ListType(cel.DynType)}, cel.BoolType,
				cel.BinaryBinding(anyInList))),
		cel.Function("domain_of",
			cel.Overload("domain_of_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(domainOf))),
		cel.Function("ratio",
			cel.Overload("ratio_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.DoubleType,
				cel.BinaryBinding(ratio))),
	)
	return cel.NewEnv(opts...)
}

func toFloat(v ref.Val) (float64, error) {
	switch n := v.(type) {
	case types.Int:
		return float64(n), nil
	case types.Uint:
		return float64(n), nil
	case types.Double:
		return float64(n), nil
	}
	return 0, fmt.Errorf("want a number, not %s", v.Type().TypeName())
}

// compile builds the CEL program of every rule, recording errors in e. It
// returns an error only when the environment itself cannot be built.
func compile(rs *Ruleset, sources []ruleSource, e *errs) error {
	env, err := newEnv(rs.lists)
	if err != nil {
		return fmt.Errorf("rules: build CEL environment: %w", err)
	}
	listNames := make([]string, 0, len(rs.lists))
	for name := range rs.lists {
		listNames = append(listNames, name)
	}
	slices.Sort(listNames)

	for i, r := range rs.rules {
		if r.When == "" {
			continue
		}
		where, when := sources[i].where, sources[i].when
		ast, iss := env.Compile(r.When)
		if iss.Err() != nil {
			for _, ce := range iss.Errors() {
				msg := strings.ReplaceAll(ce.Message, " (in container '')", "")
				e.add(exprLine(when, ce.Location.Line()), where, "when: %s (at column %d of the expression)", msg, ce.Location.Column()+1)
			}
			continue
		}
		// Map values are dyn, so `key.leaked` alone type-checks as dyn; a
		// non-bool result then fails at evaluation like any other error.
		if t := ast.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
			e.add(when.Line, where, "when must return a bool, not %s", t)
			continue
		}
		info, problems := inspect(ast.NativeRep(), rs.lists, listNames)
		for _, p := range problems {
			e.add(exprLine(when, p.line), where, "when: %s (at column %d of the expression)", p.msg, p.column)
		}
		if len(problems) > 0 {
			continue
		}
		opts := []cel.ProgramOption{cel.EvalOptions(cel.OptOptimize)}
		if info.loops {
			opts = append(opts, cel.CostLimit(MaxCost))
		}
		prg, err := env.Program(ast, opts...)
		if err != nil {
			e.add(when.Line, where, "when: %v", err)
			continue
		}
		r.program = prg
		r.expr = info
	}
	return nil
}

// exprLine maps a line of a CEL expression to a line of the YAML file. Block
// scalars (| and >) start on the line after their indicator.
func exprLine(when *yaml.Node, celLine int) int {
	if celLine < 1 {
		celLine = 1
	}
	if when.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return when.Line + celLine
	}
	return when.Line + celLine - 1
}

// exprInfo is what static inspection learns about a rule's expression.
type exprInfo struct {
	// refs are the signals the expression reads by name, such as
	// account.sends_1m. For entity, Name is the entity's name.
	refs []signalRef
	// entityRefs are the entity signals the expression reads by name, such
	// as entity.content.sends_24h: Map is the entity's name.
	entityRefs []signalRef
	// lists are the list names passed to in_list and any_in_list.
	lists []string
	// constant is true when the expression is a literal.
	constant bool
	// loops is true when the expression has a comprehension.
	loops bool
}

type signalRef struct {
	Map, Name string
}

func (r signalRef) String() string { return r.Map + "." + r.Name }

type exprProblem struct {
	line, column int
	msg          string
}

// inspect walks a checked expression to collect the signals and lists it
// reads, and to verify statically that every list it names exists.
func inspect(a *celast.AST, lists map[string][]string, listNames []string) (exprInfo, []exprProblem) {
	var info exprInfo
	var problems []exprProblem
	info.constant = a.Expr().Kind() == celast.LiteralKind
	at := func(e celast.Expr, format string, args ...any) {
		loc := a.SourceInfo().GetStartLocation(e.ID())
		problems = append(problems, exprProblem{line: loc.Line(), column: loc.Column() + 1, msg: fmt.Sprintf(format, args...)})
	}
	addRef := func(operand celast.Expr, name string) {
		if operand.Kind() != celast.IdentKind || !slices.Contains(variables, operand.AsIdent()) {
			return
		}
		ref := signalRef{Map: operand.AsIdent(), Name: name}
		if !slices.Contains(info.refs, ref) {
			info.refs = append(info.refs, ref)
		}
	}

	// addEntityRef records entity.<name>.<signal>, written with selects or
	// string indexes, when operand is entity.<name>.
	addEntityRef := func(operand celast.Expr, signal string) {
		var inner celast.Expr
		var name string
		switch operand.Kind() {
		case celast.SelectKind:
			inner, name = operand.AsSelect().Operand(), operand.AsSelect().FieldName()
		case celast.CallKind:
			call := operand.AsCall()
			switch call.FunctionName() {
			case operators.Index, operators.OptIndex, operators.OptSelect:
				if len(call.Args()) != 2 {
					return
				}
				n, ok := stringLiteral(call.Args()[1])
				if !ok {
					return
				}
				inner, name = call.Args()[0], n
			default:
				return
			}
		default:
			return
		}
		if inner.Kind() != celast.IdentKind || inner.AsIdent() != "entity" {
			return
		}
		ref := signalRef{Map: name, Name: signal}
		if !slices.Contains(info.entityRefs, ref) {
			info.entityRefs = append(info.entityRefs, ref)
		}
	}

	celast.PreOrderVisit(a.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		switch e.Kind() {
		case celast.ComprehensionKind:
			info.loops = true
		case celast.SelectKind:
			sel := e.AsSelect()
			addRef(sel.Operand(), sel.FieldName())
			addEntityRef(sel.Operand(), sel.FieldName())
		case celast.CallKind:
			call := e.AsCall()
			args := call.Args()
			switch call.FunctionName() {
			case operators.Index, operators.OptIndex, operators.OptSelect:
				if len(args) == 2 {
					if name, ok := stringLiteral(args[1]); ok {
						addRef(args[0], name)
						addEntityRef(args[0], name)
					}
				}
			case "in_list", "any_in_list":
				if len(args) != 2 || call.IsMemberFunction() {
					return
				}
				name, ok := stringLiteral(args[0])
				switch {
				case !ok:
					at(args[0], "%s: the list name must be a string literal, so it can be checked at load", call.FunctionName())
				case !hasKey(lists, name):
					at(args[0], "%s: unknown list %q%s", call.FunctionName(), name, suggest(name, listNames))
				case !slices.Contains(info.lists, name):
					info.lists = append(info.lists, name)
				}
			}
		}
	}))
	return info, problems
}

func hasKey[V any](m map[string]V, k string) bool {
	_, ok := m[k]
	return ok
}

func stringLiteral(e celast.Expr) (string, bool) {
	if e.Kind() != celast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}

// activation exposes a signal.Set to CEL. Each map is converted once per
// evaluation and shared by every rule.
type activation struct {
	maps [6]map[string]any
	vars [6]ref.Val
}

var emptySignals = map[string]any{}

func newActivation(set signal.Set) *activation {
	a := &activation{maps: [6]map[string]any{set.Event, set.Account, set.Key, set.IP, set.Domain, set.Entity}}
	for i, m := range a.maps {
		// A missing map behaves like a map with every signal absent: reading
		// from it is an evaluation error, not a null dereference.
		if m == nil {
			m = emptySignals
		}
		a.vars[i] = types.NewStringInterfaceMap(types.DefaultTypeAdapter, m)
	}
	return a
}

// absent returns which of refs named name are missing from their map.
func (a *activation) absent(refs []signalRef, name string) []string {
	var out []string
	for _, r := range refs {
		if r.Name != name {
			continue
		}
		i := slices.Index(variables, r.Map)
		if _, ok := a.maps[i][name]; !ok {
			out = append(out, r.String())
		}
	}
	return out
}

func (a *activation) ResolveName(name string) (any, bool) {
	switch name {
	case "event":
		return a.vars[0], true
	case "account":
		return a.vars[1], true
	case "key":
		return a.vars[2], true
	case "ip":
		return a.vars[3], true
	case "domain":
		return a.vars[4], true
	case "entity":
		return a.vars[5], true
	}
	return nil, false
}

func (a *activation) Parent() interpreter.Activation { return nil }
