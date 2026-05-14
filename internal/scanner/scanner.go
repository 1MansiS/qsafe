package scanner

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/1MansiS/qsafe/internal/findings"
)

type Scanner struct {
	rulesDir string
}

func New() *Scanner {
	return &Scanner{rulesDir: "rules"}
}

func NewWithRulesDir(rulesDir string) *Scanner {
	return &Scanner{rulesDir: rulesDir}
}

func (s *Scanner) ScanFile(path string) (*findings.FindingSet, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lang, ok := detectLanguage(filepath.Ext(path))
	if !ok {
		return &findings.FindingSet{}, nil
	}

	astResult, err := scanAST(content, path, lang)
	if err != nil {
		return nil, err
	}

	sgResult := runSemgrep(path, lang, s.rulesDir)

	all := append(astResult, sgResult...)
	all = deduplicate(all)
	sort.Slice(all, func(i, j int) bool {
		return all[i].Line < all[j].Line
	})

	return &findings.FindingSet{Findings: all}, nil
}
