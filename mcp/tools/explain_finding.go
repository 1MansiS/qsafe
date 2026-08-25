package tools

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/explain"
	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/ragclient"
)

// FindingParams mirrors the fields of findings.Finding a caller already
// has from a prior scan_file/assess_codebase result — pass it straight
// through rather than re-deriving it.
type FindingParams struct {
	Primitive string   `json:"primitive" jsonschema:"The crypto primitive, e.g. RSA, ECDSA, ECDH, ECC"`
	Usage     string   `json:"usage" jsonschema:"The usage category, e.g. key_generation, signing, encryption"`
	File      string   `json:"file,omitempty" jsonschema:"Source file path, for context in the response"`
	Line      int      `json:"line,omitempty" jsonschema:"Line number, for context in the response"`
	Function  string   `json:"function,omitempty" jsonschema:"Enclosing function name from the finding's context, if known"`
	InTest    bool     `json:"in_test,omitempty" jsonschema:"Whether the call site is in a _test.go file, from the finding's context"`
	Arguments []string `json:"arguments,omitempty" jsonschema:"Literal call-site argument text from the finding's context, if known"`
}

func (p *FindingParams) finding() findings.Finding {
	f := findings.Finding{Primitive: p.Primitive, Usage: p.Usage, File: p.File, Line: p.Line}
	if p.Function != "" || p.InTest || len(p.Arguments) > 0 {
		f.Context = &findings.Context{Function: p.Function, InTest: p.InTest, Arguments: p.Arguments}
	}
	return f
}

func ExplainFindingHandler(rag *ragclient.Client) func(context.Context, *sdkmcp.CallToolRequest, *FindingParams) (*sdkmcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest, params *FindingParams) (*sdkmcp.CallToolResult, any, error) {
		result, err := explain.Explain(ctx, rag, params.finding())
		if err != nil {
			return nil, nil, fmt.Errorf("explain_finding: %w", err)
		}
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: formatExplainResult(result)},
			},
		}, nil, nil
	}
}

// formatExplainResult renders the retrieved chunks + instructions as text
// for the calling model — qsafe never writes the explanation itself, see
// internal/explain's package doc.
func formatExplainResult(r *explain.Result) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Grounding context for %s %s (%s:%d):\n", r.Finding.Primitive, r.Finding.Usage, r.Finding.File, r.Finding.Line)
	for _, c := range r.Chunks {
		fmt.Fprintf(&sb, "\n[%s §%s, score %.2f]\n%s\n", c.Source, c.Section, c.Score, c.Text)
	}
	fmt.Fprintf(&sb, "\n---\n%s", r.Instructions)
	return sb.String()
}
