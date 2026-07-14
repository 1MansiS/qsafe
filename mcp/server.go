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
		Instructions: "qsafe — PQC Migration Advisor. Scans source files for classical cryptographic primitives (RSA, ECDH, ECDSA, AES-ECB, 3DES, RC4, MD5, SHA-1) and provides quantum-safe migration guidance grounded in NIST FIPS 203/204/205 and CNSA 2.0.",
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "scan_file",
		Description: "Scan a source file for quantum-vulnerable cryptographic primitives. Returns a structured list of findings with primitive type, usage, line number, and severity. Supports Go and Python.",
	}, tools.ScanFileHandler(scn))

	sdkmcp.AddTool(server, &sdkmcp.Tool{
		Name:        "assess_codebase",
		Description: "Scan an entire directory or repository for quantum-vulnerable cryptographic primitives. Walks all Go and Python source files, aggregates findings, and returns a summary grouped by primitive plus the full finding list.",
	}, tools.AssessCodebaseHandler(scn))

	return server
}
