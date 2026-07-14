package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
)

// ScanDir scans root for quantum-vulnerable crypto primitives.
// Go: walks .go files when a go.mod is present; uses go/ast import-alias tracking per file.
// Python: walks .py files via an embedded ast subprocess.
func (s *Scanner) ScanDir(root string) (*findings.CodebaseReport, error) {
	report := &findings.CodebaseReport{Root: root, ByPrimitive: map[string]int{}}

	var allFindings []findings.Finding

	// Go: one callgraph pass over the whole module.
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		gf, err := scanGoModule(root)
		if err == nil {
			allFindings = append(allFindings, gf...)
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

	// Python: per-file ast scan.
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
		if strings.ToLower(filepath.Ext(path)) != ".py" {
			return nil
		}
		report.FilesScanned++
		pf, err := scanPythonFile(path)
		if err == nil {
			allFindings = append(allFindings, pf...)
		}
		return nil
	})

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
