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
		Description: "Scan a source file for quantum-vulnerable cryptographic primitives. Returns a structured list of findings with primitive type, usage, line number, and severity. Supports Java, Python, Go, and C.",
	}, tools.ScanFileHandler(scn))

	return server
}
