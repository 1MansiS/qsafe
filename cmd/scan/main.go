package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/1MansiS/qsafe/internal/scanner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: scan <dir|https://github.com/...>")
		os.Exit(1)
	}

	target := os.Args[1]
	label := target

	if isRemoteURL(target) {
		tmp, err := cloneRepo(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, "clone failed:", err)
			os.Exit(1)
		}
		defer os.RemoveAll(tmp)
		target = tmp
	}

	s := scanner.New()
	r, err := s.ScanDir(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	fmt.Printf("Source:            %s\n", label)
	fmt.Printf("Files scanned:     %d\n", r.FilesScanned)
	fmt.Printf("Files with findings: %d\n\n", r.FilesWithFindings)
	fmt.Println("By primitive:")
	for k, v := range r.ByPrimitive {
		fmt.Printf("  %-14s %d\n", k, v)
	}
	fmt.Printf("\nFindings (%d total):\n", len(r.Findings))
	for _, f := range r.Findings {
		// For remote clones, strip the noisy temp prefix and show repo-relative paths.
		file := f.File
		if isRemoteURL(label) {
			file = repoRelative(file)
		}
		fmt.Printf("  [%-6s] %-10s %-16s %s:%d\n",
			string(f.Severity), f.Primitive, f.Usage, file, f.Line)
	}
}

func isRemoteURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "git@")
}

func cloneRepo(url string) (string, error) {
	tmp, err := os.MkdirTemp("", "qsafe-scan-*")
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "cloning %s ...\n", url)
	cmd := exec.Command("git", "clone", "--depth", "1", "--quiet", url, tmp)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	return tmp, nil
}

// repoRelative strips everything up to and including the repo root dir name,
// returning a path like "src/foo/bar.go" for display.
func repoRelative(abs string) string {
	// tmp dir is e.g. /tmp/qsafe-scan-12345/<repo files>
	// We want everything after the temp dir root.
	parts := strings.SplitN(filepath.ToSlash(abs), "/", -1)
	for i, p := range parts {
		if strings.HasPrefix(p, "qsafe-scan-") {
			if i+1 < len(parts) {
				return strings.Join(parts[i+1:], "/")
			}
		}
	}
	return abs
}
