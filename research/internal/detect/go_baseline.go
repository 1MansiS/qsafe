// GoBaselineDetector wraps qsafe's real cmd/scan binary — the existing
// go/ast-based detector — purely as the A/B comparison point for this
// experiment. It is never combined with the tree-sitter detector's output;
// the two run side by side and get diffed to decide whether tree-sitter
// replaces the go/ast approach for Go, or gets discarded. This subprocess
// call is fine here specifically because research/ never ships — same
// principle as the gosec/bandit oracle comparisons.
package detect

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
)

type GoBaselineDetector struct {
	// BinaryPath is a built qsafe cmd/scan binary:
	// go build -o qsafe-scan ./cmd/scan   (run from the qsafe repo root)
	BinaryPath string
}

func (GoBaselineDetector) Name() string { return "go-ast-baseline" }

// findingLine matches cmd/scan's report lines, e.g.:
//
//	  [high  ] RSA        key_generation   testdata/gomod/main.go:15
var findingLine = regexp.MustCompile(`(?m)^\s*\[(\S+)\s*\]\s+(\S+)\s+(\S+)\s+(.+):(\d+)\s*$`)

func (d GoBaselineDetector) Scan(repoPath string) ([]Finding, error) {
	out, err := exec.Command(d.BinaryPath, repoPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("baseline scan: %w (output: %s)", err, out)
	}

	var findings []Finding
	for _, m := range findingLine.FindAllSubmatch(out, -1) {
		line, _ := strconv.Atoi(string(m[5]))
		findings = append(findings, Finding{
			Primitive: string(m[2]),
			Usage:     string(m[3]),
			File:      string(m[4]),
			Line:      line,
		})
	}
	return findings, nil
}
