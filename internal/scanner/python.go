package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	_ "embed"

	"github.com/1MansiS/qsafe/internal/findings"
)

//go:embed pyast.py
var pyastScript []byte

type pyFinding struct {
	Primitive string `json:"primitive"`
	Usage     string `json:"usage"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Severity  string `json:"severity"`
}

func scanPythonFile(path string) ([]findings.Finding, error) {
	if _, err := exec.LookPath("python3"); err != nil {
		return nil, fmt.Errorf("python3 not found in PATH")
	}

	cmd := exec.Command("python3", "-", path)
	cmd.Stdin = bytes.NewReader(pyastScript)
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok && len(out) > 0 {
			// non-zero exit but output present — attempt to parse
		} else {
			return nil, fmt.Errorf("pyast: %w", err)
		}
	}

	var raw []pyFinding
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("pyast output: %w", err)
	}

	fs := make([]findings.Finding, 0, len(raw))
	for _, r := range raw {
		fs = append(fs, findings.Finding{
			Primitive: r.Primitive,
			Usage:     r.Usage,
			File:      r.File,
			Line:      r.Line,
			Severity:  findings.Severity(strings.ToLower(r.Severity)),
		})
	}
	return fs, nil
}
