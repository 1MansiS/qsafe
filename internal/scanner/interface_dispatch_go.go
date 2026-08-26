// Interface-dispatch heuristic for Go: finds crypto.Signer/crypto.Decrypter
// call sites with no lexical tie to any concrete crypto package — e.g.
//
//	func useSigner(s crypto.Signer, digest []byte) { s.Sign(...) }
//
// — invisible to scanGoFile's import-alias walk entirely. Also covers two
// related shapes that aren't calls through a tracked interface at all:
// functions taking `interface{}` and switching on the concrete type
// internally (golang.org/x/crypto/ssh.NewSignerFromKey), and config
// structs where a concrete key value is set on a field rather than passed
// as an argument (crypto/tls.Certificate.PrivateKey). Validated as a
// research/ prototype against 5 real repos before graduating here, plus
// gliderlabs/ssh for the ssh-specific rules, with every finding checked
// against source for false positives.
//
// Deliberately a heuristic, not sound interprocedural dataflow: no SSA, no
// callgraph — that's the documented, much more expensive, permanently
// out-of-scope full interprocedural analysis (ARCHITECTURE.md's "Analysis
// depth" section). Every finding this produces carries
// findings.ConfidenceHeuristic, never ConfidenceDirect — see
// internal/findings/findings.go's doc comment on why that distinction
// matters before treating this output with the same weight as a direct
// call.
//
// All domain knowledge (which interfaces/methods/sink functions/struct
// fields matter, which primitives implement or construct what) lives in
// rules/go/interface_dispatch.yaml — this file is a generic interpreter
// over three rule `kind`s, same discipline as callgraph_go.go's
// direct-call rules. No primitive-specific knowledge should end up
// hardcoded here.
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
	"sync"

	"golang.org/x/tools/go/packages"
	"gopkg.in/yaml.v3"

	"github.com/1MansiS/qsafe/internal/findings"
)

//go:embed rules/go/interface_dispatch.yaml
var interfaceDispatchRulesFS embed.FS

type interfaceRule struct {
	Kind string `yaml:"kind"` // "receiver" | "argument" | "struct_field"

	// interface_package/interface_name name the type checked at the match
	// site — despite the field names, isNamedType doesn't care whether
	// it's actually an interface: it's plain named-type identity, which
	// is what lets receiver/argument rules match a crypto.Signer-typed
	// expression AND struct_field rules match the composite literal's own
	// concrete type (e.g. tls.Certificate) with the same check.
	InterfacePackage string `yaml:"interface_package"`
	InterfaceName    string `yaml:"interface_name"`

	Method   string `yaml:"method"`    // kind: receiver
	Func     string `yaml:"func"`      // kind: argument — "pkgpath.FuncName", resolved via go/types object identity, so this matches methods too (e.g. "crypto/x509.CreateCRL" for (*x509.Certificate).CreateCRL)
	ArgIndex int    `yaml:"arg_index"` // kind: argument

	Field        string `yaml:"field"`         // kind: struct_field — field name to match within the composite literal (e.g. "PrivateKey")
	ValuePackage string `yaml:"value_package"` // kind: struct_field — concrete type of the field's assigned value
	ValueName    string `yaml:"value_name"`    // kind: struct_field

	Usage        string   `yaml:"usage"`
	Implementers []string `yaml:"implementers"`
}

// Loaded lazily, not via a package-level var initializer: this file is
// only ever exercised when WithInterfaceDispatch/-interface-dispatch is
// actually passed, and a package-level initializer runs unconditionally at
// package init — a malformed rules file would panic every scan, including
// plain default ones that never touch this feature, contradicting the
// documented "opt-in keeps ScanDir's default zero-setup behavior
// unchanged" guarantee. sync.Once still means the YAML is only parsed
// once, on first real use.
var (
	interfaceDispatchRulesOnce sync.Once
	interfaceDispatchRules     []interfaceRule
	interfaceDispatchRulesErr  error
)

func loadInterfaceDispatchRules() ([]interfaceRule, error) {
	interfaceDispatchRulesOnce.Do(func() {
		data, err := interfaceDispatchRulesFS.ReadFile("rules/go/interface_dispatch.yaml")
		if err != nil {
			interfaceDispatchRulesErr = fmt.Errorf("reading embedded interface_dispatch.yaml: %w", err)
			return
		}
		interfaceDispatchRules, interfaceDispatchRulesErr = parseInterfaceRules(data)
	})
	return interfaceDispatchRules, interfaceDispatchRulesErr
}

// parseInterfaceRules is the pure parsing step, split out from
// loadInterfaceDispatchRules' file I/O + caching so a malformed-YAML case
// can be tested directly without needing to corrupt the real embedded file.
func parseInterfaceRules(data []byte) ([]interfaceRule, error) {
	var rules []interfaceRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("invalid embedded interface_dispatch.yaml: %w", err)
	}
	return rules, nil
}

// scanGoModuleInterfaceDispatch type-checks root and matches
// interfaceDispatchRules against it. presentPrimitives is the set of
// primitives scanGoModule already found via direct calls elsewhere in the
// same module — a finding only fires if its candidate primitive is in that
// set, which is what keeps this from firing on every interface-typed
// variable in existence.
func scanGoModuleInterfaceDispatch(root string, presentPrimitives map[string]bool) ([]findings.Finding, error) {
	rules, err := loadInterfaceDispatchRules()
	if err != nil {
		return nil, err
	}

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
				sev, _ := severityFromString("high") // interface-dispatched Shor-broken usage — same weight class as a direct call, see Confidence for the certainty distinction instead

				switch node := n.(type) {
				case *ast.CallExpr:
					for _, rule := range rules {
						if rule.Kind == "struct_field" {
							continue
						}
						for _, prim := range matchInterfaceRule(pkg, node, rule) {
							if !presentPrimitives[prim] {
								continue
							}
							pos := pkg.Fset.Position(node.Pos())
							fs = append(fs, findings.Finding{
								Primitive:  prim,
								Usage:      rule.Usage,
								File:       pos.Filename,
								Line:       pos.Line,
								Severity:   sev,
								Confidence: findings.ConfidenceHeuristic,
								Detail:     heuristicDetail(rule, prim),
								Context:    buildContext(file, pkg.Fset, node),
							})
						}
					}

				case *ast.CompositeLit:
					for _, rule := range rules {
						if rule.Kind != "struct_field" {
							continue
						}
						value, prim := matchStructFieldRule(pkg, node, rule)
						if prim == "" || !presentPrimitives[prim] {
							continue
						}
						pos := pkg.Fset.Position(node.Pos())
						var args []string
						if value != nil {
							args = []string{exprTextFset(pkg.Fset, value)}
						}
						fs = append(fs, findings.Finding{
							Primitive:  prim,
							Usage:      rule.Usage,
							File:       pos.Filename,
							Line:       pos.Line,
							Severity:   sev,
							Confidence: findings.ConfidenceHeuristic,
							Detail:     heuristicDetail(rule, prim),
							Context:    buildContextAt(file, pkg.Fset, node.Pos(), args),
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

// matchStructFieldRule handles kind: struct_field — lit is a composite
// literal (e.g. tls.Certificate{...}, including the common &tls.Certificate{...}
// form: the & doesn't change the literal's own type, so no extra handling
// needed). Matches when lit's type is the rule's named struct AND it sets
// rule.Field to a value whose own static type is the rule's concrete
// ValuePackage/ValueName — the same "read the value expression's own type,
// not the field's declared interface type" trick argument-kind rules use
// for `interface{}`-typed parameters. Only the keyed literal form
// (Field: value) is matched; positional composite literals aren't handled,
// same "call site alone must be self-evident" policy as the rest of this
// file.
//
// Returns the matched value expression (for Context) and the single
// candidate primitive, or (nil, "") if nothing matched. Unlike
// matchInterfaceRule's implementers list (one interface, several possible
// concrete implementers), a struct_field rule already names one concrete
// value type, so rule.Implementers is always exactly one entry here.
func matchStructFieldRule(pkg *packages.Package, lit *ast.CompositeLit, rule interfaceRule) (ast.Expr, string) {
	t := pkg.TypesInfo.TypeOf(lit)
	if t == nil || !isNamedType(t, rule.InterfacePackage, rule.InterfaceName) {
		return nil, ""
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != rule.Field {
			continue
		}
		vt := pkg.TypesInfo.TypeOf(kv.Value)
		if vt == nil || !isNamedType(vt, rule.ValuePackage, rule.ValueName) {
			return nil, ""
		}
		if len(rule.Implementers) == 0 {
			return nil, ""
		}
		return kv.Value, rule.Implementers[0]
	}
	return nil, ""
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
			"heuristic: arg[%d] of %s (%s.%s-typed) — %s is constructed directly elsewhere in this module, not proven to reach this call site",
			rule.ArgIndex, rule.Func, rule.InterfacePackage, rule.InterfaceName, prim)
	case "struct_field":
		return fmt.Sprintf(
			"heuristic: %s.%s{%s: ...} set to a %s.%s value — %s is constructed directly elsewhere in this module, not proven to reach this call site",
			rule.InterfacePackage, rule.InterfaceName, rule.Field, rule.ValuePackage, rule.ValueName, prim)
	default:
		return fmt.Sprintf(
			"heuristic: %s call via %s.%s — %s is constructed directly elsewhere in this module, not proven to reach this call site",
			rule.Method, rule.InterfacePackage, rule.InterfaceName, prim)
	}
}

// isNamedType reports whether t (after unwrapping one level of pointer —
// needed for e.g. *rsa.PrivateKey, the conventional way Go crypto private
// keys are passed) is the named type pkgPath.name (e.g. "crypto"/"Signer",
// or a concrete type like "crypto/rsa"/"PrivateKey" — this check doesn't
// care whether the named type is an interface, see interfaceRule's doc
// comment). String-matches on the type's own path/name rather than loading
// and comparing types.Object identity — simple, and robust enough for
// stdlib types with unambiguous names.
func isNamedType(t types.Type, pkgPath, name string) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath
}
