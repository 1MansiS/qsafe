// Command research runs the tree-sitter-go prototype and the existing
// go/ast baseline against the same Go codebase and reports where they
// agree and disagree, scoped to Shor-broken findings only. Throwaway —
// answers one question (is tree-sitter worth switching to for Go) and
// gets deleted once that's decided.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"

	"qsafe-research/internal/detect"
)

func main() {
	baselineBin := flag.String("baseline-bin", "", "path to a built qsafe cmd/scan binary")
	types := flag.Bool("types", false, "run the go/types interface-dispatch heuristic instead of the tree-sitter-vs-baseline comparison")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: research [-baseline-bin path | -types] <repo-dir-or-url>")
		os.Exit(1)
	}
	target := flag.Arg(0)

	repoPath, cleanup, err := resolveRepo(target)
	if err != nil {
		log.Fatalf("resolve repo: %v", err)
	}
	defer cleanup()

	if *types {
		runTypesDetector(repoPath, *baselineBin)
		return
	}

	detectors := []detect.Detector{detect.GoTreeSitterDetector{}}
	if *baselineBin != "" {
		detectors = append(detectors, detect.GoBaselineDetector{BinaryPath: *baselineBin})
	}

	results := map[string][]detect.Finding{}
	for _, d := range detectors {
		fs, err := d.Scan(repoPath)
		if err != nil {
			log.Fatalf("%s: %v", d.Name(), err)
		}
		results[d.Name()] = fs
		fmt.Printf("%-18s %d findings\n", d.Name(), len(fs))
	}

	if len(detectors) == 2 {
		diff(results[detectors[0].Name()], results[detectors[1].Name()], detectors[0].Name(), detectors[1].Name())
	}
}

// runTypesDetector prints every interface-dispatch finding with its Detail
// text, since the whole point of this run is inspecting the heuristic's
// reasoning and false-positive rate by hand, not a count.
func runTypesDetector(repoPath, baselineBin string) {
	if baselineBin == "" {
		log.Fatal("-types requires -baseline-bin (a built qsafe cmd/scan binary)")
	}
	fs, err := detect.GoTypesDetector{BaselineBinaryPath: baselineBin}.Scan(repoPath)
	if err != nil {
		log.Fatalf("go-types-interface: %v", err)
	}
	fmt.Printf("go-types-interface  %d findings\n\n", len(fs))
	for _, f := range fs {
		fmt.Printf("  [%s] %s:%d\n    %s\n", f.Primitive, f.File, f.Line, f.Detail)
	}
}

func resolveRepo(target string) (path string, cleanup func(), err error) {
	if len(target) > 4 && (target[:4] == "http" || target[:4] == "git@") {
		tmp, err := os.MkdirTemp("", "qsafe-research-*")
		if err != nil {
			return "", nil, err
		}
		cmd := exec.Command("git", "clone", "--depth", "1", "--quiet", target, tmp)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.RemoveAll(tmp)
			return "", nil, err
		}
		return tmp, func() { os.RemoveAll(tmp) }, nil
	}
	return target, func() {}, nil
}

// diff reports file:line+primitive-level agreement and disagreement between
// two finding sets. Neither side is treated as ground truth — this is a
// symmetric A/B comparison, not a pass/fail check.
func diff(a, b []detect.Finding, nameA, nameB string) {
	key := func(f detect.Finding) string { return fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Primitive) }

	setA := map[string]detect.Finding{}
	for _, f := range a {
		setA[key(f)] = f
	}
	setB := map[string]detect.Finding{}
	for _, f := range b {
		setB[key(f)] = f
	}

	var onlyA, onlyB, both []string
	for k := range setA {
		if _, ok := setB[k]; ok {
			both = append(both, k)
		} else {
			onlyA = append(onlyA, k)
		}
	}
	for k := range setB {
		if _, ok := setA[k]; !ok {
			onlyB = append(onlyB, k)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)

	fmt.Printf("\nagreement: %d\n", len(both))
	fmt.Printf("only in %s (%d):\n", nameA, len(onlyA))
	for _, k := range onlyA {
		fmt.Printf("  %s\n", k)
	}
	fmt.Printf("only in %s (%d):\n", nameB, len(onlyB))
	for _, k := range onlyB {
		fmt.Printf("  %s\n", k)
	}
}
