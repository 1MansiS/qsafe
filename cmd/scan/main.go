package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/scanner"
)

func main() {
	// Named -interface-dispatch, not -deep: this repo explicitly rejected
	// full SSA/CHA interprocedural analysis ("--deep mode" in the original
	// design) as permanently out of scope — see ARCHITECTURE.md's "Analysis
	// depth" section. This flag enables a much lighter go/types heuristic
	// instead (scanner.WithInterfaceDispatch), a different feature; reusing
	// the old name would wrongly imply it's a smaller version of the
	// rejected mode rather than a distinct, deliberately-scoped one.
	interfaceDispatch := flag.Bool("interface-dispatch", false, "also run the go/types interface-dispatch heuristic (needs a buildable module — resolved deps, Go toolchain, possibly network)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: scan [-interface-dispatch] <dir|https://github.com/...>")
		os.Exit(1)
	}

	target := flag.Arg(0)
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

	var opts []scanner.ScanOption
	if *interfaceDispatch {
		opts = append(opts, scanner.WithInterfaceDispatch())
	}

	s := scanner.New()
	r, err := s.ScanDir(target, opts...)
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
		conf := ""
		if f.Confidence == findings.ConfidenceHeuristic {
			conf = "  (" + f.Detail + ")"
		}
		fmt.Printf("  [%-6s] %-10s %-16s %s:%d%s\n",
			string(f.Severity), f.Primitive, f.Usage, file, f.Line, conf)
		if f.Context != nil {
			fmt.Printf("      %s\n", f.Context.String())
		}
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
