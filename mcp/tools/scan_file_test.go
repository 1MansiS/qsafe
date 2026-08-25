package tools

import (
	"strings"
	"testing"

	"github.com/1MansiS/qsafe/internal/scanner"
)

// TestFormatFindings_SurfacesContext is a regression test for a code-review
// finding: formatFindings printed Severity/Primitive/Usage/Line/Detail but
// never Context or an explicit Confidence marker, so a calling model had no
// way to know it should pass function/in_test/arguments along on a
// follow-up explain_finding/suggest_migration call — the Context feature
// worked in unit tests and the cmd/scan CLI but was silently unreachable in
// the actual MCP tool-chaining flow.
func TestFormatFindings_SurfacesContext(t *testing.T) {
	s := scanner.New()
	fs, err := s.ScanFile("../../testdata/gomod/main.go")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	out := formatFindings("../../testdata/gomod/main.go", fs)

	if !strings.Contains(out, "context:") {
		t.Errorf("expected formatFindings to include a context line, got:\n%s", out)
	}
	if !strings.Contains(out, "useRSA()") {
		t.Errorf("expected the enclosing function to be surfaced, got:\n%s", out)
	}
	if !strings.Contains(out, "rand.Reader") {
		t.Errorf("expected argument text to be surfaced, got:\n%s", out)
	}
}

// TestFormatReport_SurfacesContext is the same regression test for
// assess_codebase's formatReport, which had the identical gap.
func TestFormatReport_SurfacesContext(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/gomod")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	out := formatReport(report)

	if !strings.Contains(out, "context:") {
		t.Errorf("expected formatReport to include a context line, got:\n%s", out)
	}
	if !strings.Contains(out, "useRSA()") {
		t.Errorf("expected the enclosing function to be surfaced, got:\n%s", out)
	}
}
