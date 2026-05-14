package scanner

import "github.com/1MansiS/qsafe/internal/findings"

func deduplicate(in []findings.Finding) []findings.Finding {
	type key struct {
		file      string
		line      int
		primitive string
	}
	seen := make(map[key]bool)
	out := make([]findings.Finding, 0, len(in))
	for _, f := range in {
		k := key{f.File, f.Line, f.Primitive}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
