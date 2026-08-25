package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
)

// ScanOption configures an individual ScanDir call. Variadic and additive
// so existing ScanDir(root) callers are unaffected.
type ScanOption func(*scanOptions)

type scanOptions struct {
	interfaceDispatch bool
}

// WithInterfaceDispatch enables the Go interface-dispatch heuristic (see
// interface_dispatch_go.go) — crypto.Signer/crypto.Decrypter call sites
// with no lexical tie to a concrete crypto package. Off by default: unlike
// the rest of the scanner, it needs a *buildable* module (go/packages —
// resolved deps, Go toolchain, possibly network) and its findings carry
// findings.ConfidenceHeuristic, not ConfidenceDirect. Opt-in keeps
// ScanDir's default zero-setup behavior unchanged.
func WithInterfaceDispatch() ScanOption {
	return func(o *scanOptions) { o.interfaceDispatch = true }
}

// ScanDir scans root for quantum-vulnerable crypto primitives. Go only —
// walks .go files when a go.mod is present, using go/ast import-alias
// tracking per file. See qsafe.md's "design for uniformity, build for Go
// only" note: other languages are deliberately out of scope for now, not
// forgotten.
func (s *Scanner) ScanDir(root string, opts ...ScanOption) (*findings.CodebaseReport, error) {
	var o scanOptions
	for _, opt := range opts {
		opt(&o)
	}

	report := &findings.CodebaseReport{Root: root, ByPrimitive: map[string]int{}}

	var allFindings []findings.Finding

	// Go: one callgraph pass over the whole module.
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		gf, err := scanGoModule(root)
		if err == nil {
			allFindings = append(allFindings, gf...)
		}
		if o.interfaceDispatch {
			present := map[string]bool{}
			for _, f := range gf {
				present[f.Primitive] = true
			}
			if idf, err := scanGoModuleInterfaceDispatch(root, present); err == nil {
				allFindings = append(allFindings, idf...)
			}
			// best-effort, same policy as the direct scan above: an
			// unbuildable module (no network, unresolved deps) shouldn't
			// fail the whole scan, just skip the heuristic pass.
		}
		// Count .go source files (excluding .git and vendor).
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if info.Name() == ".git" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.ToLower(filepath.Ext(path)) == ".go" {
				report.FilesScanned++
			}
			return nil
		})
	}

	allFindings = deduplicate(allFindings)
	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].File != allFindings[j].File {
			return allFindings[i].File < allFindings[j].File
		}
		return allFindings[i].Line < allFindings[j].Line
	})

	filesSeen := map[string]bool{}
	for _, f := range allFindings {
		report.Findings = append(report.Findings, f)
		report.ByPrimitive[f.Primitive]++
		filesSeen[f.File] = true
	}
	report.FilesWithFindings = len(filesSeen)

	return report, nil
}
