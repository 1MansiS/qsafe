package tools

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/scanner"
)

type ScanFileParams struct {
	Path string `json:"path" jsonschema:"Absolute path to the source file to scan for quantum-vulnerable cryptographic primitives"`
}

func ScanFileHandler(s *scanner.Scanner) func(context.Context, *sdkmcp.CallToolRequest, *ScanFileParams) (*sdkmcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest, params *ScanFileParams) (*sdkmcp.CallToolResult, any, error) {
		fs, err := s.ScanFile(params.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("scan failed: %w", err)
		}
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: formatFindings(params.Path, fs)},
			},
		}, nil, nil
	}
}

func formatFindings(path string, fs *findings.FindingSet) string {
	if len(fs.Findings) == 0 {
		return fmt.Sprintf("No quantum-vulnerable cryptographic primitives found in %s.", path)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d quantum-vulnerable cryptographic primitive(s) in %s:\n", len(fs.Findings), path)

	for _, f := range fs.Findings {
		fmt.Fprintf(&sb, "\n  [%s] %s (%s) — line %d", strings.ToUpper(string(f.Severity)), f.Primitive, f.Usage, f.Line)
		if f.Detail != "" {
			fmt.Fprintf(&sb, "\n    %s", f.Detail)
		}
	}

	sb.WriteString("\n\nUse explain_finding or suggest_migration for remediation guidance.")
	return sb.String()
}
