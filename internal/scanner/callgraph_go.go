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

// scanGoFile parses one Go file and returns findings based on import-alias
// tracking: for each call X.Fn(...) where X is a local alias for a crypto
// import, emit a finding. It also resolves one hop of indirection — a
// variable assigned a crypto function value directly (`fn := rsa.GenerateKey`)
// and later invoked as `fn(...)` — by pre-scanning assignments before
// walking calls. No type checking or dependency loading required, so deeper
// indirection (interface dispatch, multi-hop reassignment) is out of scope;
// see ARCHITECTURE.md's `--deep` mode.
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
			ref, ok := varFuncs[fun.Name]
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
// pkg is a known crypto import alias — and returns name → resolved primitive.
func resolveGoVarFuncRefs(f *ast.File, imports map[string]string) map[string]varFuncRef {
	refs := make(map[string]varFuncRef)

	resolve := func(lhsName string, rhs ast.Expr) {
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
		refs[lhsName] = varFuncRef{
			primitive:  rule.Primitive,
			usage:      usage,
			via:        ident.Name + "." + fn,
			importPath: importPath,
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec: // var name = pkg.Fn
			for i, name := range node.Names {
				if i < len(node.Values) {
					resolve(name.Name, node.Values[i])
				}
			}
		case *ast.AssignStmt: // name := pkg.Fn  or  name = pkg.Fn
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					continue
				}
				if ident, ok := lhs.(*ast.Ident); ok {
					resolve(ident.Name, node.Rhs[i])
				}
			}
		}
		return true
	})
	return refs
}

