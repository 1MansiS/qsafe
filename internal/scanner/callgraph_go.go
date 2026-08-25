package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
)

// Primitive/usage/severity knowledge lives in rules/go/*.yaml (loaded into
// goRulesByImport, see rules.go) — not hardcoded here. Adding a new
// package or function means editing YAML, not rebuilding the binary logic.

// scanGoModule walks all .go files under root and scans each one.
// It uses go/parser + go/ast per file — no type checking, no SSA, no callgraph.
// This keeps memory flat at O(1 file) regardless of module size.
func scanGoModule(root string) ([]findings.Finding, error) {
	var all []findings.Finding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".go" {
			return nil
		}
		fs, _ := scanGoFile(path)
		all = append(all, fs...)
		return nil
	})
	return all, err
}

// varFuncRef records that a local variable was assigned a bare function
// value from a crypto package (e.g. `keyGen := rsa.GenerateKey`), so calls
// through that variable can still be attributed back to the crypto call.
type varFuncRef struct {
	primitive  string
	usage      string
	via        string // e.g. "rsa.GenerateKey" — the original selector, for Detail text
	importPath string // for severity lookup back into goRulesByImport
}

// varFuncKey scopes a varFuncRef binding to the function it was declared
// in ("" for package-level), so a local variable in one function can never
// match a call to a same-named-but-unrelated variable in a different
// function — see the bug this fixes: a bare-name-only map let
// `keyGen := add` in an unrelated function get misattributed to whatever
// crypto primitive some other `keyGen` happened to be bound to elsewhere
// in the file.
type varFuncKey struct {
	scope string // enclosing function name, "" for package scope
	name  string
}

// scanGoFile parses one Go file and returns findings based on import-alias
// tracking: for each call X.Fn(...) where X is a local alias for a crypto
// import, emit a finding. It also resolves one hop of indirection — a
// variable assigned a crypto function value directly (`fn := rsa.GenerateKey`)
// and later invoked as `fn(...)` — by pre-scanning assignments before
// walking calls, scoped to the enclosing function the same way Go's own
// shadowing rules work (a local binding is only visible within its own
// function; package-level bindings are visible everywhere unless shadowed).
// No type checking or dependency loading required, so deeper indirection
// (interface dispatch is a separate, opt-in heuristic — see
// interface_dispatch_go.go; multi-hop reassignment stays out of scope) —
// see ARCHITECTURE.md's "Analysis depth" section.
func scanGoFile(path string) ([]findings.Finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, nil // skip files with syntax errors
	}

	// Build local alias → canonical import path map.
	imports := make(map[string]string)
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		var localName string
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			localName = imp.Name.Name
		} else {
			localName = importPath[strings.LastIndex(importPath, "/")+1:]
		}
		imports[localName] = importPath
	}

	// Pass 1: find `name := pkg.Fn` / `var name = pkg.Fn` bindings (bare
	// function value, not a call) where pkg resolves to a crypto import.
	// Package-level `var` decls can lexically appear after their use within
	// the same file, so this must run as a separate pass before the call walk.
	varFuncs := resolveGoVarFuncRefs(f, imports)
	locallyShadowed := collectLocalDecls(f)

	var fs []findings.Finding
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		var fn, prim, usage string
		var detail string

		var rule goRule
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			ident, ok := fun.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath, ok := imports[ident.Name]
			if !ok {
				return true
			}
			rule, ok = goRulesByImport[importPath]
			if !ok {
				return true
			}
			fn = fun.Sel.Name
			usage, ok = rule.Functions[fn] // allowlist: unlisted functions in a
			if !ok {                       // known-crypto package are not findings
				return true
			}
			prim = rule.Primitive

		case *ast.Ident:
			callScope, _ := enclosingFuncName(f, call.Pos())
			ref, ok := varFuncs[varFuncKey{callScope, fun.Name}]
			if !ok {
				if locallyShadowed[varFuncKey{callScope, fun.Name}] {
					// A local declaration of this name exists in this scope
					// but isn't itself crypto-bound (e.g. `keyGen := add`) —
					// it still shadows any package-level binding of the same
					// name, the same way Go's own scoping works. Must not
					// fall through to the package-level match below.
					return true
				}
				ref, ok = varFuncs[varFuncKey{"", fun.Name}] // fall back to a genuine package-level binding
			}
			if !ok {
				return true
			}
			prim, usage = ref.primitive, ref.usage
			detail = "indirect: " + fun.Name + " = " + ref.via
			rule = goRulesByImport[ref.importPath]

		default:
			return true
		}

		sev, _ := severityFromString(rule.Severity)
		pos := fset.Position(call.Pos())
		fs = append(fs, findings.Finding{
			Primitive:  prim,
			Usage:      usage,
			File:       pos.Filename,
			Line:       pos.Line,
			Severity:   sev,
			Confidence: findings.ConfidenceDirect, // both direct calls and one-hop
			Detail:     detail,                    // indirection are unambiguous — no interface dispatch involved
			Context:    buildContext(f, fset, call),
		})
		return true
	})
	return fs, nil
}

// resolveGoVarFuncRefs walks the whole file for `var name = pkg.Fn` and
// `name := pkg.Fn` assignments — a bare selector RHS (no call parens) where
// pkg is a known crypto import alias — and returns each binding keyed by
// (enclosing function, name), so lookups at the call site can only match
// within the same scope (or fall back to a genuine package-level binding).
func resolveGoVarFuncRefs(f *ast.File, imports map[string]string) map[varFuncKey]varFuncRef {
	refs := make(map[varFuncKey]varFuncRef)

	resolve := func(lhsName string, rhs ast.Expr, declPos token.Pos) {
		sel, ok := rhs.(*ast.SelectorExpr)
		if !ok {
			return
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return
		}
		importPath, ok := imports[ident.Name]
		if !ok {
			return
		}
		rule, ok := goRulesByImport[importPath]
		if !ok {
			return
		}
		fn := sel.Sel.Name
		usage, ok := rule.Functions[fn] // same allowlist as the direct-call path
		if !ok {
			return
		}
		scope, _ := enclosingFuncName(f, declPos) // "" if this is a package-level declaration
		refs[varFuncKey{scope, lhsName}] = varFuncRef{
			primitive:  rule.Primitive,
			usage:      usage,
			via:        ident.Name + "." + fn,
			importPath: importPath,
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec: // var name = pkg.Fn — package-level or local
			for i, name := range node.Names {
				if i < len(node.Values) {
					resolve(name.Name, node.Values[i], node.Pos())
				}
			}
		case *ast.AssignStmt: // name := pkg.Fn  or  name = pkg.Fn — always local
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					continue
				}
				if ident, ok := lhs.(*ast.Ident); ok {
					resolve(ident.Name, node.Rhs[i], node.Pos())
				}
			}
		}
		return true
	})
	return refs
}

// collectLocalDecls returns every (scope, name) pair declared locally
// anywhere in f — via `:=`, `var` (with or without an initializer), or as a
// function parameter — regardless of whether that declaration resolves to
// a tracked crypto binding. This is what lets the lookup in scanGoFile tell
// "no local binding at all, safe to fall back to package scope" apart from
// "there IS a local binding here, it's just not a crypto one" — the second
// case must still block the fallback, the same way Go's own shadowing
// rules work: once a name is redeclared locally, the outer one is never
// visible in that scope again, regardless of what the local one holds.
func collectLocalDecls(f *ast.File) map[varFuncKey]bool {
	shadowed := make(map[varFuncKey]bool)
	mark := func(name string, pos token.Pos) {
		if scope, ok := enclosingFuncName(f, pos); ok {
			shadowed[varFuncKey{scope, name}] = true
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, name := range node.Names {
				mark(name.Name, node.Pos())
			}
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						mark(ident.Name, node.Pos())
					}
				}
			}
		case *ast.FuncDecl:
			// enclosingFuncName matches on the *body's* position range, so
			// parameters (which sit before the body starts) need to be
			// marked using a position inside the body, not the FuncDecl's
			// own Pos() (the "func" keyword) — that would never match.
			if node.Body != nil && node.Type.Params != nil {
				for _, field := range node.Type.Params.List {
					for _, name := range field.Names {
						mark(name.Name, node.Body.Pos())
					}
				}
			}
		}
		return true
	})
	return shadowed
}

