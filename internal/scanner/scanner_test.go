package scanner_test

import (
	"testing"

	"github.com/1MansiS/qsafe/internal/scanner"
)

func TestScanFile_Python(t *testing.T) {
	s := scanner.New()
	fs, err := s.ScanFile("../../testdata/vulnerable_crypto.py")
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	want := []string{"RSA", "ECDSA/ECDH", "AES-ECB", "3DES", "RC4", "MD5", "SHA-1"}
	found := map[string]bool{}
	for _, f := range fs.Findings {
		found[f.Primitive] = true
	}
	for _, prim := range want {
		if !found[prim] {
			t.Errorf("expected primitive %q in findings, got: %v", prim, fs.Findings)
		}
	}
}

func TestScanDir_Go(t *testing.T) {
	s := scanner.New()
	report, err := s.ScanDir("../../testdata/gomod")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	want := []string{"RSA", "ECDSA", "3DES", "DES", "RC4", "MD5", "SHA-1"}
	for _, prim := range want {
		if report.ByPrimitive[prim] == 0 {
			t.Errorf("expected primitive %q in report, got ByPrimitive: %v", prim, report.ByPrimitive)
		}
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
