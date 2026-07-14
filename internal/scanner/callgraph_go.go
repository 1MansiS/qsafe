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

// goCryptoTargets maps canonical stdlib import path → default [primitive, usage].
var goCryptoTargets = map[string][2]string{
	"crypto/rsa":      {"RSA", "encryption"},
	"crypto/ecdsa":    {"ECDSA", "signing"},
	"crypto/ecdh":     {"ECDH", "key_agreement"},
	"crypto/des":      {"DES", "encryption"},
	"crypto/md5":      {"MD5", "hashing"},
	"crypto/sha1":     {"SHA-1", "hashing"},
	"crypto/rc4":      {"RC4", "encryption"},
	"crypto/elliptic": {"ECC", "key_generation"},
}

// fnPrimitive overrides the package-level primitive for specific function names.
var fnPrimitive = map[string]string{
	"NewTripleDESCipher": "3DES",
}

// fnUsage overrides the package-level usage for specific function names.
var fnUsage = map[string]string{
	"GenerateKey":     "key_generation",
	"Sign":            "signing",
	"SignASN1":        "signing",
	"Verify":          "signing",
	"VerifyASN1":      "signing",
	"SignPKCS1v15":    "signing",
	"SignPSS":         "signing",
	"VerifyPKCS1v15":  "signing",
	"VerifyPSS":       "signing",
	"EncryptPKCS1v15": "encryption",
	"DecryptPKCS1v15": "encryption",
	"EncryptOAEP":     "encryption",
	"DecryptOAEP":     "encryption",
	"NewCipher":       "encryption",
	"XORKeyStream":    "encryption",
	"New":             "hashing",
	"Sum":             "hashing",
}

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

// scanGoFile parses one Go file and returns findings based on import-alias
// tracking: for each call X.Fn(...) where X is a local alias for a crypto
// import, emit a finding. No type checking or dependency loading required.
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

	var fs []findings.Finding
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath, ok := imports[ident.Name]
		if !ok {
			return true
		}
		target, ok := goCryptoTargets[importPath]
		if !ok {
			return true
		}

		fn := sel.Sel.Name
		prim := target[0]
		if override, ok := fnPrimitive[fn]; ok {
			prim = override
		}
		usage := target[1]
		if u, ok := fnUsage[fn]; ok {
			usage = u
		}

		pos := fset.Position(call.Pos())
		fs = append(fs, findings.Finding{
			Primitive: prim,
			Usage:     usage,
			File:      pos.Filename,
			Line:      pos.Line,
			Severity:  severityForPrimitive(prim),
		})
		return true
	})
	return fs, nil
}

func severityForPrimitive(prim string) findings.Severity {
	switch prim {
	case "RSA", "ECDH", "ECDSA", "ECDSA/ECDH", "3DES", "DES", "RC4":
		return findings.SeverityHigh
	default:
		return findings.SeverityMedium
	}
}
