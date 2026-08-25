// Package detect's tree-sitter-go implementation. Deliberately thin: all
// domain knowledge (which package+function pairs are Shor-broken) lives in
// queries/go/shor.scm as literal-matched patterns. This file only runs the
// query and turns a fired capture name (`finding.<Primitive>.<Usage>`) into
// a Finding — no lookup table, no primitive/usage knowledge in Go source.
package detect

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	tsgo "github.com/smacker/go-tree-sitter/golang"
)

const findingCapturePrefix = "finding."

// GoTreeSitterDetector reads its query from disk at Scan time (go:embed
// can't reference paths outside its own package directory) — not worth
// restructuring the tree for a throwaway tool.
type GoTreeSitterDetector struct {
	// QueryPath defaults to queries/go/shor.scm relative to cwd if empty.
	QueryPath string
}

func (GoTreeSitterDetector) Name() string { return "treesitter-go" }

func (d GoTreeSitterDetector) Scan(repoPath string) ([]Finding, error) {
	queryPath := d.QueryPath
	if queryPath == "" {
		queryPath = "queries/go/shor.scm"
	}
	querySrc, err := os.ReadFile(queryPath)
	if err != nil {
		return nil, err
	}

	lang := tsgo.GetLanguage()
	query, err := sitter.NewQuery(querySrc, lang)
	if err != nil {
		return nil, err
	}
	defer query.Close()

	var all []Finding
	err = filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".go" {
			return nil
		}
		fs, err := scanOneGoFile(path, lang, query)
		if err != nil {
			return nil // skip unparseable files, same policy as callgraph_go.go
		}
		all = append(all, fs...)
		return nil
	})
	return all, err
}

func scanOneGoFile(path string, lang *sitter.Language, query *sitter.Query) ([]Finding, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(lang)
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil || tree == nil {
		return nil, err
	}
	defer tree.Close()

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()
	cursor.Exec(query, tree.RootNode())

	var findings []Finding
	for {
		m, ok := cursor.NextMatch()
		if !ok {
			break
		}
		m = cursor.FilterPredicates(m, src) // apply #eq?/#any-of? — Exec alone doesn't filter
		for _, c := range m.Captures {
			name := query.CaptureNameForId(c.Index)
			if !strings.HasPrefix(name, findingCapturePrefix) {
				continue // helper captures like _pkg/_fn, used only by predicates
			}
			// "finding.RSA.key_generation" -> primitive="RSA", usage="key_generation"
			parts := strings.SplitN(strings.TrimPrefix(name, findingCapturePrefix), ".", 2)
			if len(parts) != 2 {
				continue
			}
			findings = append(findings, Finding{
				Primitive: parts[0],
				Usage:     parts[1],
				File:      path,
				Line:      int(c.Node.StartPoint().Row) + 1,
			})
		}
	}
	return findings, nil
}
