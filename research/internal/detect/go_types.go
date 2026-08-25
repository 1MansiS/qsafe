// GoTypesDetector prototypes the interface-dispatch heuristic: find call
// sites through crypto.Signer/crypto.Decrypter (no lexical tie to any
// concrete crypto package), and attribute them to a primitive only if that
// primitive's key type is known to implement the interface *and* the same
// module also directly constructs that primitive somewhere (via
// GoBaselineDetector's findings, reused rather than reimplemented).
//
// This is deliberately a heuristic, not sound interprocedural dataflow —
// treat its output with lower confidence than a direct-call finding. No
// SSA, no callgraph; this stands in for that much more expensive,
// permanently out-of-scope full interprocedural analysis.
//
// All domain knowledge (which interfaces/methods/sink functions matter,
// which primitives implement what) lives in rules/go/interface_dispatch.yaml
// — this file is a generic interpreter over two rule `kind`s, same
// discipline as rules.go's direct-call rules. No primitive-specific
// knowledge should ever end up hardcoded here again.
package detect

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"

	"golang.org/x/tools/go/packages"
	"gopkg.in/yaml.v3"
)

type interfaceRule struct {
	Kind             string   `yaml:"kind"` // "receiver" | "argument"
	InterfacePackage string   `yaml:"interface_package"`
	InterfaceName    string   `yaml:"interface_name"`
	Method           string   `yaml:"method"`   // kind: receiver
	Func             string   `yaml:"func"`     // kind: argument — "pkgpath.FuncName"
	ArgIndex         int      `yaml:"arg_index"` // kind: argument
	Usage            string   `yaml:"usage"`
	Implementers     []string `yaml:"implementers"`
}

type GoTypesDetector struct {
	// BaselineBinaryPath is a built qsafe cmd/scan binary, same as
	// GoBaselineDetector.BinaryPath.
	BaselineBinaryPath string
	// RulesPath defaults to rules/go/interface_dispatch.yaml relative to
	// cwd if empty — read from disk rather than go:embed, same reasoning
	// as GoTreeSitterDetector's QueryPath (embed can't reach outside its
	// own package directory).
	RulesPath string
}

func (GoTypesDetector) Name() string { return "go-types-interface" }

func (d GoTypesDetector) Scan(repoPath string) ([]Finding, error) {
	rules, err := loadInterfaceRules(d.rulesPath())
	if err != nil {
		return nil, fmt.Errorf("interface_dispatch.yaml: %w", err)
	}

	// Step 1: which primitives are directly constructed anywhere in this
	// module? Reuses the real scanner's own output rather than
	// reimplementing direct-call matching a third time.
	direct, err := GoBaselineDetector{BinaryPath: d.BaselineBinaryPath}.Scan(repoPath)
	if err != nil {
		return nil, fmt.Errorf("direct scan (for candidate primitives): %w", err)
	}
	presentPrimitives := map[string]bool{}
	for _, f := range direct {
		presentPrimitives[f.Primitive] = true
	}

	// Step 2: type-check the module and match both rule kinds. Needs a
	// buildable module — resolved deps, Go toolchain — a real precondition
	// change from the zero-setup go/parser approach.
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Dir: repoPath,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("packages.Load: %w", err)
	}

	var findings []Finding
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			continue // skip packages that don't build cleanly, same "best effort" policy as the rest of the scanner
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				for _, rule := range rules {
					for _, prim := range matchInterfaceRule(pkg, call, rule) {
						if !presentPrimitives[prim] {
							continue // that primitive isn't constructed anywhere in this module
						}
						pos := pkg.Fset.Position(call.Pos())
						findings = append(findings, Finding{
							Primitive: prim,
							Usage:     rule.Usage,
							File:      pos.Filename,
							Line:      pos.Line,
							Detail:    heuristicDetail(rule, prim),
						})
					}
				}
				return true
			})
		}
	}
	return findings, nil
}

// matchInterfaceRule returns the candidate primitives if call matches rule,
// or nil. Both `kind`s reduce to the same check — "is this expression's
// static type the named interface" — just applied to a different position
// in the call (the receiver, or one specific argument).
func matchInterfaceRule(pkg *packages.Package, call *ast.CallExpr, rule interfaceRule) []string {
	var target ast.Expr

	switch rule.Kind {
	case "receiver":
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != rule.Method {
			return nil
		}
		target = sel.X

	case "argument":
		if !calleeIs(pkg, call, rule.Func) {
			return nil
		}
		if rule.ArgIndex >= len(call.Args) {
			return nil
		}
		target = call.Args[rule.ArgIndex]

	default:
		return nil
	}

	t := pkg.TypesInfo.TypeOf(target)
	if t == nil || !isNamedType(t, rule.InterfacePackage, rule.InterfaceName) {
		return nil
	}
	return rule.Implementers
}

// calleeIs reports whether call invokes the function named pkgPath.FuncName
// — resolved via go/types' own object resolution (Uses), not import-alias
// string matching, so it's correct regardless of local import aliasing or
// dot-imports for free.
func calleeIs(pkg *packages.Package, call *ast.CallExpr, wantFullName string) bool {
	var ident *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	default:
		return false
	}
	fn, ok := pkg.TypesInfo.Uses[ident].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	return fn.Pkg().Path()+"."+fn.Name() == wantFullName
}

func heuristicDetail(rule interfaceRule, prim string) string {
	switch rule.Kind {
	case "argument":
		return fmt.Sprintf(
			"heuristic: %s argument to %s (%s.%s-typed) — %s is constructed directly elsewhere in this module, not proven to reach this call site",
			ordinal(rule.ArgIndex), rule.Func, rule.InterfacePackage, rule.InterfaceName, prim)
	default:
		return fmt.Sprintf(
			"heuristic: %s call via %s.%s — %s is constructed directly elsewhere in this module, not proven to reach this call site",
			rule.Method, rule.InterfacePackage, rule.InterfaceName, prim)
	}
}

func ordinal(i int) string {
	return fmt.Sprintf("arg[%d]", i)
}

// isNamedType reports whether t is the named type pkgPath.name (e.g.
// "crypto"/"Signer"), string-matching on the type's own path/name rather
// than loading and comparing types.Object identity — simpler for a spike,
// robust enough for stdlib interfaces with unambiguous names.
func isNamedType(t types.Type, pkgPath, name string) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath
}

func (d GoTypesDetector) rulesPath() string {
	if d.RulesPath != "" {
		return d.RulesPath
	}
	return "rules/go/interface_dispatch.yaml"
}

func loadInterfaceRules(path string) ([]interfaceRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []interfaceRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
