# qsafe

**PQC Migration Advisor.** Scans Go codebases for classical cryptographic
primitives that Shor's algorithm breaks (RSA, ECDSA, ECDH, ECC, ED25519,
not general crypto hygiene issues like MD5/SHA-1), and is building toward
RAG-grounded migration guidance over NIST's post-quantum standards
(FIPS 203/204/205, CNSA 2.0). Exposed as an MCP server for use directly
inside Claude, Cursor, or any MCP-compatible host, plus a standalone CLI.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, data flow
diagram, and build plan.

## Status

- **Phase 1 (static analysis): complete.** Direct-call detection for
  RSA/ECDSA/ECDH/ECC/ED25519, plus an opt-in `go/types` interface-dispatch
  heuristic for cases where the concrete crypto package isn't lexically
  visible at the call site. Validated against several real-world Go repos
  (cfssl, boulder, vault, caddy, smallstep/certificates, wireguard-go,
  gliderlabs/ssh). See `internal/scanner`'s rule files for specifics.
- **Phase 2 (RAG retrieval): in progress.** The ingestion pipeline
  (`rag-pipeline/ingest/`) has a working PDF-to-chunk path for FIPS 203;
  the migration lookup table, hand-authored playbooks, embedding, and the
  Go-side retrieval (`internal/rag`) aren't built yet. `explain_finding`/
  `suggest_migration` are wired up in Go but still point at a stub.

## Quick start

```bash
go build ./...
go test ./...

# Standalone CLI scanner — a local directory or a GitHub URL
go run ./cmd/scan <dir|https://github.com/...>
go run ./cmd/scan -interface-dispatch <dir>   # also run the heuristic pass (needs a buildable module)

# MCP server
go run ./cmd/mcp-server
```

Drop-in config for Claude Code / Cursor: [.mcp.json.example](.mcp.json.example).

## Scope

Go only, for now. See [CLAUDE.md](CLAUDE.md) for the reasoning and what's
deliberately deferred. Detection rules are YAML, not hardcoded Go
(`internal/scanner/rules/go/`). Adding a new primitive or function means
editing config, not rebuilding the binary's logic.

## License

Apache 2.0. See [LICENSE](LICENSE).
