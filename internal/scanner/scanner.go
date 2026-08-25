package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) ScanFile(path string) (*findings.FindingSet, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	var fs []findings.Finding
	var err error

	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		fs, err = scanGoFile(path)
	default:
		return &findings.FindingSet{}, nil
	}
	if err != nil {
		return nil, err
	}

	fs = deduplicate(fs)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
	return &findings.FindingSet{Findings: fs}, nil
}
