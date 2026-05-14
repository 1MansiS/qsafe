package mcp

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/ragclient"
)

func NewServer(rag *ragclient.Client) *sdkmcp.Server {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "qsafe",
		Version: "0.1.0",
	}, &sdkmcp.ServerOptions{
		Instructions: "qsafe — PQC Migration Advisor. Scans code for classical cryptographic primitives and provides quantum-safe migration guidance grounded in NIST FIPS 203/204/205 and CNSA 2.0.",
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "ping",
		Description: "Health check — confirms the MCP server can reach the RAG service. Remove in Phase 1.",
	}, func(ctx context.Context, req *sdkmcp.CallToolRequest, _ any) (*sdkmcp.CallToolResult, any, error) {
		chunks, err := rag.Retrieve(ctx, ragclient.RetrieveRequest{
			Primitive: "RSA-2048",
			Usage:     "key_exchange",
			TopK:      1,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("RAG service unreachable: %w", err)
		}
		var sb strings.Builder
		sb.WriteString("qsafe MCP server is up. RAG service is reachable.\n\nTest chunk from /retrieve:\n")
		for _, c := range chunks {
			sb.WriteString(c.Text)
		}
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: sb.String()},
			},
		}, nil, nil
	})

	return server
}
