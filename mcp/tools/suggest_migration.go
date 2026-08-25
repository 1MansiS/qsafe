package tools

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/explain"
	"github.com/1MansiS/qsafe/internal/ragclient"
)

func SuggestMigrationHandler(rag *ragclient.Client) func(context.Context, *sdkmcp.CallToolRequest, *FindingParams) (*sdkmcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest, params *FindingParams) (*sdkmcp.CallToolResult, any, error) {
		result, err := explain.SuggestMigration(ctx, rag, params.finding())
		if err != nil {
			return nil, nil, fmt.Errorf("suggest_migration: %w", err)
		}
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: formatExplainResult(result)}, // same rendering — grounding + instructions, no LLM call
			},
		}, nil, nil
	}
}
