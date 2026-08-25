package mcp

import (
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/ragclient"
	"github.com/1MansiS/qsafe/internal/scanner"
	"github.com/1MansiS/qsafe/mcp/tools"
)

func NewServer(rag *ragclient.Client, scn *scanner.Scanner) *sdkmcp.Server {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "qsafe",
		Version: "0.1.0",
	}, &sdkmcp.ServerOptions{
		Instructions: "qsafe — PQC Migration Advisor. Scans Go source for Shor-broken cryptographic primitives (RSA, ECDSA, ECDH, ECC) and provides quantum-safe migration guidance grounded in NIST FIPS 203/204/205 and CNSA 2.0.",
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "scan_file",
		Description: "Scan a Go source file for Shor-broken cryptographic primitives. Returns a structured list of findings with primitive type, usage, line number, severity, and confidence (direct call vs. heuristic interface-dispatch attribution).",
	}, tools.ScanFileHandler(scn))

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "assess_codebase",
		Description: "Scan an entire Go directory or repository for Shor-broken cryptographic primitives, aggregates findings, and returns a summary grouped by primitive plus the full finding list.",
	}, tools.AssessCodebaseHandler(scn))

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "explain_finding",
		Description: "Retrieve grounded NIST FIPS 203/204/205 and CNSA 2.0 context for a finding from scan_file/assess_codebase, plus instructions for explaining why it's quantum-vulnerable. Does not generate the explanation itself — returns citations for you (the calling model) to write it from.",
	}, tools.ExplainFindingHandler(rag))

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "suggest_migration",
		Description: "Retrieve grounded migration-playbook context for a finding from scan_file/assess_codebase, plus instructions for proposing a before/after code change to its PQC equivalent. Does not generate the migration plan itself — returns citations for you (the calling model) to write it from.",
	}, tools.SuggestMigrationHandler(rag))

	return server
}
