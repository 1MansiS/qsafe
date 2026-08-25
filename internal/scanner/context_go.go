// Per-call-site context extraction, shared by callgraph_go.go's direct-call
// path and interface_dispatch_go.go's heuristic path — same AST walk each
// is already doing, just reading a bit more off the nodes it visits. See
// findings.Context's doc comment for what this deliberately does and
// doesn't capture.
package scanner

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
)

// buildContext returns per-call-site context for call, or nil if there's
// nothing worth reporting (no enclosing function found and no arguments —
// shouldn't happen in practice for a real call expression, but keeps the
// pointer nil rather than an empty-but-non-nil struct when truly nothing
// was extracted).
func buildContext(file *ast.File, fset *token.FileSet, call *ast.CallExpr) *findings.Context {
	fn, _ := enclosingFuncName(file, call.Pos())
	args := argumentTexts(fset, call)
	if fn == "" && len(args) == 0 {
		return nil
	}
	pos := fset.Position(call.Pos())
	return &findings.Context{
		Function:  fn,
		InTest:    strings.HasSuffix(pos.Filename, "_test.go"),
		Arguments: args,
	}
}

// enclosingFuncName finds which top-level function or method declaration
// contains pos, if any (e.g. a call at package scope, in a var
// initializer, has no enclosing function). Includes the receiver type for
// methods, e.g. "(*SoftCAS).GetSigner".
func enclosingFuncName(file *ast.File, pos token.Pos) (string, bool) {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if pos < fd.Body.Pos() || pos > fd.Body.End() {
			continue
		}
		if fd.Recv == nil || len(fd.Recv.List) == 0 {
			return fd.Name.Name, true
		}
		return "(" + exprText(fd.Recv.List[0].Type) + ")." + fd.Name.Name, true
	}
	return "", false
}

// argumentTexts returns the source text of every argument to call, in
// order — e.g. rsa.GenerateKey(rand.Reader, 2048) -> ["rand.Reader", "2048"].
// Not restricted to literals; go/printer handles any expression uniformly.
func argumentTexts(fset *token.FileSet, call *ast.CallExpr) []string {
	if len(call.Args) == 0 {
		return nil
	}
	args := make([]string, len(call.Args))
	for i, arg := range call.Args {
		args[i] = exprTextFset(fset, arg)
	}
	return args
}

func exprText(e ast.Expr) string {
	return exprTextFset(nil, e)
}

func exprTextFset(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if fset == nil {
		fset = token.NewFileSet()
	}
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return "?"
	}
	return buf.String()
}
