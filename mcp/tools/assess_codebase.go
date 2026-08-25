package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/scanner"
)

type AssessCodebaseParams struct {
	Path string `json:"path" jsonschema:"Absolute path to a directory or repository root to scan for quantum-vulnerable cryptographic primitives"`
}

func AssessCodebaseHandler(s *scanner.Scanner) func(context.Context, *sdkmcp.CallToolRequest, *AssessCodebaseParams) (*sdkmcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest, params *AssessCodebaseParams) (*sdkmcp.CallToolResult, any, error) {
		report, err := s.ScanDir(params.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("assess failed: %w", err)
		}
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: formatReport(report)},
			},
		}, nil, nil
	}
}

func formatReport(r *findings.CodebaseReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Scanned %d source file(s) under %s — %d finding(s) across %d file(s).\n",
		r.FilesScanned, r.Root, len(r.Findings), r.FilesWithFindings)

	if len(r.ByPrimitive) > 0 {
		sb.WriteString("\nBy primitive:\n")
		primitives := make([]string, 0, len(r.ByPrimitive))
		for p := range r.ByPrimitive {
			primitives = append(primitives, p)
		}
		sort.Strings(primitives)
		for _, p := range primitives {
			fmt.Fprintf(&sb, "  %-10s %d\n", p, r.ByPrimitive[p])
		}
	}

	if len(r.Findings) > 0 {
		sb.WriteString("\nFindings:\n")
		for _, f := range r.Findings {
			conf := ""
			if f.Confidence == findings.ConfidenceHeuristic {
				conf = "  [heuristic]"
			}
			fmt.Fprintf(&sb, "  [%s] %s:%d %s (%s)%s\n", strings.ToUpper(string(f.Severity)), f.File, f.Line, f.Primitive, f.Usage, conf)
			if f.Detail != "" {
				fmt.Fprintf(&sb, "      %s\n", f.Detail)
			}
			if f.Context != nil {
				fmt.Fprintf(&sb, "      context: %s\n", f.Context.String())
			}
		}
	}

	sb.WriteString("\nUse explain_finding or suggest_migration for remediation guidance — pass each finding's function/in_test/arguments (from its context line above) along for richer grounding.")
	return sb.String()
}
