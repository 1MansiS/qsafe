// Interface-dispatch heuristic for Go: finds crypto.Signer/crypto.Decrypter
// call sites with no lexical tie to any concrete crypto package — e.g.
//
//	func useSigner(s crypto.Signer, digest []byte) { s.Sign(...) }
//
// — invisible to scanGoFile's import-alias walk entirely. Validated as a
// research/ prototype against 5 real repos before graduating here; see
// qsafe.md for the full before/after evidence and false-positive review.
//
// Deliberately a heuristic, not sound interprocedural dataflow: no SSA, no
// callgraph — that's the documented, much more expensive `--deep` mode
// (ARCHITECTURE.md). Every finding this produces carries
// findings.ConfidenceHeuristic, never ConfidenceDirect — see
// internal/findings/findings.go's doc comment on why that distinction
// matters before treating this output with the same weight as a direct
// call.
//
// All domain knowledge (which interfaces/methods/sink functions matter,
// which primitives implement what) lives in rules/go/interface_dispatch.yaml
// — this file is a generic interpreter over two rule `kind`s, same
// discipline as callgraph_go.go's direct-call rules. No primitive-specific
// knowledge should end up hardcoded here.
//
// Real precondition change from the rest of the scanner: this needs a
// *buildable* module (go/packages — resolved deps, Go toolchain, possibly
// network for uncached deps), not just readable .go files. That's why it's
// opt-in (scanner.WithInterfaceDispatch()) rather than always-on — ScanDir's
// zero-setup default behavior stays zero-setup.
package scanner

import (
	"embed"
	"fmt"
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/packages"
	"gopkg.in/yaml.v3"

	"github.com/1MansiS/qsafe/internal/findings"
)

//go:embed rules/go/interface_dispatch.yaml
var interfaceDispatchRulesFS embed.FS

type interfaceRule struct {
	Kind             string   `yaml:"kind"` // "receiver" | "argument"
	InterfacePackage string   `yaml:"interface_package"`
	InterfaceName    string   `yaml:"interface_name"`
	Method           string   `yaml:"method"`    // kind: receiver
	Func             string   `yaml:"func"`      // kind: argument — "pkgpath.FuncName"
	ArgIndex         int      `yaml:"arg_index"` // kind: argument
	Usage            string   `yaml:"usage"`
	Implementers     []string `yaml:"implementers"`
}

var interfaceDispatchRules = mustLoadInterfaceRules()

func mustLoadInterfaceRules() []interfaceRule {
	data, err := interfaceDispatchRulesFS.ReadFile("rules/go/interface_dispatch.yaml")
	if err != nil {
		panic(fmt.Sprintf("scanner: reading embedded interface_dispatch.yaml: %v", err))
	}
	var rules []interfaceRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		panic(fmt.Sprintf("scanner: invalid embedded interface_dispatch.yaml: %v", err))
	}
	return rules
}

// scanGoModuleInterfaceDispatch type-checks root and matches
// interfaceDispatchRules against it. presentPrimitives is the set of
// primitives scanGoModule already found via direct calls elsewhere in the
// same module — a finding only fires if its candidate primitive is in that
// set, which is what keeps this from firing on every interface-typed
// variable in existence.
func scanGoModuleInterfaceDispatch(root string, presentPrimitives map[string]bool) ([]findings.Finding, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Dir: root,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("packages.Load: %w", err)
	}

	var fs []findings.Finding
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			continue // skip packages that don't build cleanly, same "best effort" policy as scanGoModule
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				for _, rule := range interfaceDispatchRules {
					for _, prim := range matchInterfaceRule(pkg, call, rule) {
						if !presentPrimitives[prim] {
							continue
						}
						sev, _ := severityFromString("high") // interface-dispatched Shor-broken usage — same weight class as a direct call, see Confidence for the certainty distinction instead
						pos := pkg.Fset.Position(call.Pos())
						fs = append(fs, findings.Finding{
							Primitive:  prim,
							Usage:      rule.Usage,
							File:       pos.Filename,
							Line:       pos.Line,
							Severity:   sev,
							Confidence: findings.ConfidenceHeuristic,
							Detail:     heuristicDetail(rule, prim),
							Context:    buildContext(file, pkg.Fset, call),
						})
					}
				}
				return true
			})
		}
	}
	return fs, nil
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
	if rule.Kind == "argument" {
		return fmt.Sprintf(
			"heuristic: arg[%d] of %s (%s.%s-typed) — %s is constructed directly elsewhere in this module, not proven to reach this call site",
			rule.ArgIndex, rule.Func, rule.InterfacePackage, rule.InterfaceName, prim)
	}
	return fmt.Sprintf(
		"heuristic: %s call via %s.%s — %s is constructed directly elsewhere in this module, not proven to reach this call site",
		rule.Method, rule.InterfacePackage, rule.InterfaceName, prim)
}

// isNamedType reports whether t is the named type pkgPath.name (e.g.
// "crypto"/"Signer"), string-matching on the type's own path/name rather
// than loading and comparing types.Object identity — simple, and robust
// enough for stdlib interfaces with unambiguous names.
func isNamedType(t types.Type, pkgPath, name string) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath
}
