package scanner_test

import (
	"testing"

	"github.com/1MansiS/qsafe/internal/scanner"
)

func hasPrimitive(t *testing.T, path, prim string) {
	t.Helper()
	s := scanner.New()
	fs, err := s.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile(%q): %v", path, err)
	}
	for _, f := range fs.Findings {
		if f.Primitive == prim {
			return
		}
	}
	t.Errorf("expected primitive %q in %s, got findings: %v", prim, path, fs.Findings)
}

func TestScanFile_Java(t *testing.T) {
	path := "../../testdata/VulnerableCrypto.java"
	for _, prim := range []string{"RSA", "ECDH", "ECDSA", "AES-ECB", "3DES", "RC4", "MD5", "SHA-1"} {
		t.Run(prim, func(t *testing.T) {
			hasPrimitive(t, path, prim)
		})
	}
}

func TestScanFile_Python(t *testing.T) {
	path := "../../testdata/vulnerable_crypto.py"
	for _, prim := range []string{"RSA", "ECDH", "AES-ECB", "3DES", "RC4", "MD5", "SHA-1"} {
		t.Run(prim, func(t *testing.T) {
			hasPrimitive(t, path, prim)
		})
	}
}

func TestScanFile_Go(t *testing.T) {
	path := "../../testdata/vulnerable_crypto.go"
	for _, prim := range []string{"RSA", "ECDSA", "3DES", "DES", "RC4", "MD5", "SHA-1"} {
		t.Run(prim, func(t *testing.T) {
			hasPrimitive(t, path, prim)
		})
	}
}

func TestScanFile_UnsupportedExtension(t *testing.T) {
	s := scanner.New()
	fs, err := s.ScanFile("../../go.mod")
	if err != nil {
		t.Fatalf("unexpected error for unsupported file: %v", err)
	}
	if len(fs.Findings) != 0 {
		t.Errorf("expected no findings for unsupported file, got %d", len(fs.Findings))
	}
}

func TestScanFile_MissingFile(t *testing.T) {
	s := scanner.New()
	_, err := s.ScanFile("nonexistent.java")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
