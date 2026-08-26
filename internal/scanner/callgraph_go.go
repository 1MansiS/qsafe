package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/ast/astutil"

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
	importPath string // kept for Detail/debugging; severity is captured directly below
	severity   string // captured at resolution time, since goRulesByImport can hold more than one rule per import (see its doc comment) and a bare importPath lookup can't disambiguate which one this binding came from
}

// varFuncKey scopes a varFuncRef binding to the *block* it was declared in
// (the Pos() of the innermost enclosing *ast.BlockStmt; token.NoPos for
// package scope) — real Go lexical scoping, not just "which function":
// a local variable in one function can never match a call to a
// same-named-but-unrelated variable in a different function, and a name
// shadowed inside one if/for block doesn't affect the rest of the
// enclosing function outside that block. Function-level-only scoping was
// tried first and found to have exactly that second gap — a block-local
// shadow incorrectly blocked resolution for the rest of the function too.
type varFuncKey struct {
	scope token.Pos
	name  string
}

// enclosingBlockChain returns the Pos() of every *ast.BlockStmt enclosing
// pos, innermost first, followed by a final token.NoPos representing
// package scope (always present, so callers can walk the chain outward
// and are guaranteed to reach a terminal fallback).
func enclosingBlockChain(file *ast.File, pos token.Pos) []token.Pos {
	path, _ := astutil.PathEnclosingInterval(file, pos, pos)
	var chain []token.Pos
	for _, n := range path {
		if b, ok := n.(*ast.BlockStmt); ok {
			chain = append(chain, b.Pos())
		}
	}
	return append(chain, token.NoPos)
}

// declaringScope is enclosingBlockChain(file, pos)[0] — the *immediate*
// enclosing block of a declaration site (or token.NoPos if it's at
// package level), used when recording where a name was bound.
func declaringScope(file *ast.File, pos token.Pos) token.Pos {
	return enclosingBlockChain(file, pos)[0]
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
		var sevStr string

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
			fn = fun.Sel.Name
			rule, ok := findGoRule(importPath, fn) // allowlist: unlisted functions in a
			if !ok {                               // known-crypto package are not findings
				return true
			}
			usage = rule.Functions[fn]
			prim = rule.Primitive
			sevStr = rule.Severity

		case *ast.Ident:
			// Walk the real scope chain outward, innermost block first,
			// stopping at the first block that declares this name at all —
			// whether that declaration is crypto-bound (use it) or not
			// (shadowed, stop searching outward without a match). This is
			// what makes a block-local `keyGen := add` only shadow within
			// its own block, not the whole enclosing function, while still
			// correctly blocking a same-named package-level crypto binding
			// from leaking into that block.
			var ref varFuncRef
			var found bool
			for _, scope := range enclosingBlockChain(f, call.Pos()) {
				if r, ok := varFuncs[varFuncKey{scope, fun.Name}]; ok {
					ref, found = r, true
					break
				}
				if locallyShadowed[varFuncKey{scope, fun.Name}] {
					break
				}
			}
			if !found {
				return true
			}
			prim, usage = ref.primitive, ref.usage
			detail = "indirect: " + fun.Name + " = " + ref.via
			sevStr = ref.severity

		default:
			return true
		}

		sev, _ := severityFromString(sevStr)
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
		fn := sel.Sel.Name
		rule, ok := findGoRule(importPath, fn) // same allowlist as the direct-call path
		if !ok {
			return
		}
		refs[varFuncKey{declaringScope(f, declPos), lhsName}] = varFuncRef{
			primitive:  rule.Primitive,
			usage:      rule.Functions[fn],
			via:        ident.Name + "." + fn,
			importPath: importPath,
			severity:   rule.Severity,
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
		shadowed[varFuncKey{declaringScope(f, pos), name}] = true
	}
	markAt := func(name string, scope token.Pos) {
		shadowed[varFuncKey{scope, name}] = true
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
			// Parameters belong exactly to the function's own top-level
			// block — node.Body *is* that *ast.BlockStmt — so its Pos() is
			// used directly as the scope, rather than querying
			// declaringScope at some position inside the body (which would
			// need to land past the opening brace to unambiguously resolve
			// to this exact block rather than its own Pos() boundary).
			if node.Body != nil && node.Type.Params != nil {
				for _, field := range node.Type.Params.List {
					for _, name := range field.Names {
						markAt(name.Name, node.Body.Pos())
					}
				}
			}
		}
		return true
	})
	return shadowed
}
