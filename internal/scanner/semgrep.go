package scanner

import (
	"encoding/json"
	"os/exec"
	"path/filepath"

	"github.com/1MansiS/qsafe/internal/findings"
)

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string            `json:"message"`
		Metadata map[string]string `json:"metadata"`
	} `json:"extra"`
}

// runSemgrep runs semgrep against path using rules in rulesDir/langName.
// Returns nil silently if semgrep is not installed or rules are missing.
func runSemgrep(path string, lang language, rulesDir string) []findings.Finding {
	if _, err := exec.LookPath("semgrep"); err != nil {
		return nil
	}

	ruleDir := filepath.Join(rulesDir, langName(lang))

	out, err := exec.Command(
		"semgrep",
		"--config", ruleDir,
		"--json",
		"--no-git-ignore",
		"--quiet",
		path,
	).Output()
	if err != nil {
		return nil
	}

	var result semgrepOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil
	}

	var fs []findings.Finding
	for _, r := range result.Results {
		prim := r.Extra.Metadata["primitive"]
		usage := r.Extra.Metadata["usage"]
		if prim == "" {
			continue
		}
		fs = append(fs, findings.Finding{
			Primitive: prim,
			Usage:     usage,
			File:      path,
			Line:      r.Start.Line,
			Severity:  severityForPrimitive(prim),
		})
	}
	return fs
}

func severityForPrimitive(prim string) findings.Severity {
	switch prim {
	case "RSA", "ECDH", "ECDSA", "3DES", "DES", "RC4":
		return findings.SeverityHigh
	default:
		return findings.SeverityMedium
	}
}
