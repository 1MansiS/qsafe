# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**qsafe** is a PQC (Post-Quantum Cryptography) Migration Advisor. It scans codebases for classical cryptographic primitives (RSA, ECDH, ECDSA, AES-ECB, etc.) and uses RAG over NIST PQC standards (FIPS 203/204/205, CNSA 2.0) to generate concrete, spec-grounded migration guidance. The primary interface is an **MCP server** consumed by Claude, Cursor, or any MCP-compatible host.

Module path: `github.com/1MansiS/qsafe`

## Build & Run Commands

### Go (MCP server)
```bash
go build ./...
go test ./...
go run ./cmd/mcp-server        # MCP server (primary)
go run ./cmd/qsafe             # CLI (v2, future)
```

### Python (RAG pipeline)
```bash
cd rag-pipeline
pip install -r requirements.txt   # (not yet created)
uvicorn api.main:app --port 8000  # RAG FastAPI service

# Ingest corpus into Qdrant
python -m ingest.loader
python -m ingest.chunker
python -m ingest.embedder
```

### Full stack
```bash
docker-compose up   # Starts: Qdrant (:6333) + RAG service (:8000) + MCP server (:8080)
```

To connect an MCP client, copy `.mcp.json.example` → `.mcp.json` and point it at `http://localhost:8080/mcp`.

## Architecture

Two services, clean boundary:

**Go MCP server** (`cmd/mcp-server`, `mcp/`, `internal/`) — long-running Streamable HTTP server at `/mcp`. Registers four tools. Static analysis runs entirely in Go; for explanation/migration, it calls the Python RAG service over HTTP.

**Python RAG service** (`rag-pipeline/`) — internal FastAPI service, not user-facing. Exposes `POST /retrieve` → returns top-k chunks from the FIPS/CNSA corpus. Uses LlamaIndex + Qdrant with hybrid retrieval (dense embeddings via `text-embedding-3-small` + BM25 for exact token matching on algorithm identifiers).

### The Four MCP Tools

| Tool | Uses RAG? | Description |
|---|---|---|
| `scan_file(path)` | No | AST (tree-sitter) + Semgrep rules → `FindingSet` |
| `explain_finding(finding)` | Yes | Why quantum-vulnerable, which NIST standard applies |
| `suggest_migration(finding)` | Yes | Before/after code, replacement library, hybrid-mode caveat |
| `assess_codebase(path)` | Partially | CBOM + CNSA 2.0 compliance gap report across a full repo |

### Shared Core

`internal/scanner/` is imported by both the MCP server and future CLI — write static analysis logic there, not in `mcp/tools/`. `internal/findings/` defines the `Finding` / `FindingSet` types shared across both entrypoints.

### RAG Retrieval Flow

```
primitive + usage context
    → hybrid retrieval (dense + BM25)
    → cross-encoder reranking
    → metadata filter (primitive_type, operation)
    → top-k chunks → injected into LLM prompt
```

Corpus lives in `rag-pipeline/corpus/`: FIPS 203/204/205 PDFs, CNSA 2.0, RFC 9180, and hand-authored migration playbooks in `corpus/annotations/` (these are the primary differentiation — curated RSA→ML-KEM, ECDH→ML-KEM, ECDSA→ML-DSA migration guides).

### Semgrep Rules

Language-specific YAML rules live in `rules/{java,python,go,c}/`. Java and Python are highest-priority (from Veracode SAST background). Rules target the same primitives as the AST visitors — both mechanisms run in `scan_file` and results are deduplicated.

## Current State

The repo is at **Phase 0 (scaffold)** — all `.go` and `.py` files are stubs. The build plan in `ARCHITECTURE.md` defines 6 phases. Phase 1 (static analysis engine) is the next milestone.

Key external dependencies not yet added to `go.mod`:
- `modelcontextprotocol/go-sdk` — MCP server framework
- `smacker/go-tree-sitter` — multi-language AST parsing

Python dependencies (not yet in requirements.txt):
- `fastapi`, `uvicorn`, `llama-index`, `qdrant-client`, `sentence-transformers`
