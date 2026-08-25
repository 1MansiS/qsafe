// Package detect defines the technology-agnostic seam: main.go and
// internal/compare only ever see Finding and Detector. Swapping the
// underlying parsing approach later means rewriting the implementations in
// this package, not anything that consumes them.
package detect

type Finding struct {
	Primitive string
	Usage     string
	File      string
	Line      int
	Detail    string // e.g. "indirect: ECC_ALGO field" — empty for direct matches
}

type Detector interface {
	// Name identifies the detector in reports, e.g. "treesitter-go".
	Name() string
	// Scan walks repoPath and returns every Shor-broken finding.
	Scan(repoPath string) ([]Finding, error)
}
