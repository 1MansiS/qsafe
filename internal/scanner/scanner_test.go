package scanner_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/scanner"
)

// TestScanDir_Go covers the Shor-broken-only scope (see rules/go/shor.yaml):
// RSA/ECDSA/ECC should be found; testdata/gomod/main.go deliberately also
// contains 3DES/DES/RC4/MD5/SHA-1 to confirm they're correctly *excluded*
// now that the tool's scope is PQC migration, not general crypto hygiene.
func TestScanDir_Go(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/gomod")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	want := []string{"RSA", "ECDSA", "ECC"}
	for _, prim := range want {
		if report.ByPrimitive[prim] == 0 {
			t.Errorf("expected primitive %q in report, got ByPrimitive: %v", prim, report.ByPrimitive)
		}
	}
	outOfScope := []string{"3DES", "DES", "RC4", "MD5", "SHA-1"}
	for _, prim := range outOfScope {
		if report.ByPrimitive[prim] != 0 {
			t.Errorf("expected %q to be out of scope (not Shor-broken), but found %d", prim, report.ByPrimitive[prim])
		}
	}
	for _, f := range report.Findings {
		if f.Confidence != findings.ConfidenceDirect {
			t.Errorf("expected every Go direct-call finding to have Confidence=direct, got %q for %s:%d", f.Confidence, f.File, f.Line)
		}
	}
}

// TestScanDir_Go_Context covers per-call-site Context — enclosing function
// name and literal argument text, extracted by the same walk that already
// produces the finding. testdata/gomod/main.go's useRSA() is:
//
//	func useRSA() {
//		key, _ := rsa.GenerateKey(rand.Reader, 2048)
//		_ = key
//	}
func TestScanDir_Go_Context(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/gomod")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	var rsaFinding *findings.Finding
	for i, f := range report.Findings {
		if f.Primitive == "RSA" {
			rsaFinding = &report.Findings[i]
		}
	}
	if rsaFinding == nil {
		t.Fatalf("expected an RSA finding, got: %v", report.Findings)
	}
	if rsaFinding.Context == nil {
		t.Fatalf("expected Context to be populated, got nil")
	}
	if rsaFinding.Context.Function != "useRSA" {
		t.Errorf("expected enclosing function %q, got %q", "useRSA", rsaFinding.Context.Function)
	}
	if rsaFinding.Context.InTest {
		t.Errorf("expected InTest=false for a non-_test.go file")
	}
	wantArgs := []string{"rand.Reader", "2048"}
	if !reflect.DeepEqual(rsaFinding.Context.Arguments, wantArgs) {
		t.Errorf("expected Arguments %v, got %v", wantArgs, rsaFinding.Context.Arguments)
	}
}

// TestScanDir_Go_Indirection_ScopeIsolation is a regression test for a
// code-review finding: resolveGoVarFuncRefs used to key bindings by bare
// variable name across the whole file, so an unrelated local `keyGen`
// (shadowing a package-level crypto-bound `keyGen` with a completely
// different function value) got misattributed to RSA. See
// testdata/scoped_indirect_gomod for the exact reproduction.
func TestScanDir_Go_Indirection_ScopeIsolation(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/scoped_indirect_gomod")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if report.ByPrimitive["RSA"] != 1 {
		t.Errorf("expected exactly 1 RSA finding (the real, package-level keyGen usage), got ByPrimitive: %v", report.ByPrimitive)
	}
	for _, f := range report.Findings {
		if f.Line == 22 { // keyGen(1, 2) inside unrelated() — must never be flagged
			t.Errorf("unrelated()'s locally-shadowed keyGen was incorrectly flagged: %+v", f)
		}
	}
}

// TestScanDir_Go_Indirection_BlockScope is a regression test for a gap
// found while reviewing the ScopeIsolation fix above: shadowing was scoped
// to the enclosing *function*, not the enclosing *block*, so a block-local
// shadow (inside an if/for) incorrectly blocked resolution for the rest of
// the function too, not just within that block. See testdata/blockscope_check.
func TestScanDir_Go_Indirection_BlockScope(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/blockscope_check")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if report.ByPrimitive["RSA"] != 1 {
		t.Fatalf("expected exactly 1 RSA finding (the call outside the if-block), got ByPrimitive: %v", report.ByPrimitive)
	}
	if report.Findings[0].Line != 25 { // keyGen(rand.Reader, 2048), after the if-block
		t.Errorf("expected the RSA finding at line 25 (outside the if-block), got line %d", report.Findings[0].Line)
	}
}

// TestScanDir_Go_Indirection covers one-hop function-value indirection:
// `var keyGen = rsa.GenerateKey; keyGen(...)` should still be attributed to
// RSA. It also documents what the *default* (opt-in features off) scan
// misses: interface-dispatched calls (`s.Sign(...)` on a stdlib
// crypto.Signer) aren't resolved without type information — that's a
// separate, opt-in heuristic (TestScanDir_Go_InterfaceDispatch), not
// something the zero-setup default does.
func TestScanDir_Go_Indirection(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/indirect_gomod")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if report.ByPrimitive["RSA"] != 1 {
		t.Errorf("expected exactly 1 RSA finding (via keyGen indirection), got ByPrimitive: %v", report.ByPrimitive)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected exactly 1 total finding (interface dispatch stays undetected), got: %v", report.Findings)
	}
	if !strings.Contains(report.Findings[0].Detail, "indirect:") {
		t.Errorf("expected Detail to flag indirection, got %q", report.Findings[0].Detail)
	}
}

// TestScanDir_Go_InterfaceDispatch covers the graduated go/types heuristic
// (WithInterfaceDispatch) — off by default (see TestScanDir_Go_Indirection,
// which already confirms this same fixture's interface-dispatch call site
// is invisible without the option), on when opted in. Validated against 5
// real repos as a research/ prototype before graduating.
func TestScanDir_Go_InterfaceDispatch(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/indirect_gomod", scanner.WithInterfaceDispatch())
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	var got *findings.Finding
	for i, f := range report.Findings {
		if f.Confidence == findings.ConfidenceHeuristic {
			got = &report.Findings[i]
		}
	}
	if got == nil {
		t.Fatalf("expected one heuristic finding (the crypto.Signer call in useSigner), got: %v", report.Findings)
	}
	if got.Primitive != "RSA" {
		t.Errorf("expected RSA (the only primitive constructed in this module), got %q", got.Primitive)
	}
	if !strings.Contains(got.Detail, "heuristic:") {
		t.Errorf("expected Detail to flag this as heuristic, got %q", got.Detail)
	}
}

func TestScanFile_UnsupportedExtension(t *testing.T) {
	s := scanner.New()
	fs, err := s.ScanFile("../../go.mod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs.Findings) != 0 {
		t.Errorf("expected no findings for unsupported file, got %d", len(fs.Findings))
	}
}

func TestScanFile_MissingFile(t *testing.T) {
	s := scanner.New()
	_, err := s.ScanFile("nonexistent.go")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
