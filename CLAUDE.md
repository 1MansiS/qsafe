# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**qsafe** is a PQC (Post-Quantum Cryptography) Migration Advisor. It scans Go codebases for **Shor-broken** cryptographic primitives (RSA, ECDSA, ECDH, ECC — the ones Shor's algorithm actually breaks, not general crypto hygiene issues like MD5/SHA-1) and uses RAG over NIST PQC standards (FIPS 203/204/205, CNSA 2.0) to generate concrete, spec-grounded migration guidance. The primary interface is an **MCP server** consumed by Claude, Cursor, or any MCP-compatible host.

Module path: `github.com/1MansiS/qsafe`

**Scope, deliberately:** Go only, for now. Python/Java support is deferred, not abandoned — see `internal/scanner`'s history for what existed before (a Python scanner was built, then removed to keep the repo focused; Java was never built). When picking this back up, design shared pieces (like `internal/findings.Finding`) for multi-language uniformity, but don't build language support speculatively.

## Build & Run Commands

```bash
go build ./...
go test ./...
go run ./cmd/scan <dir|https://github.com/...>   # standalone CLI scanner
go run ./cmd/scan -interface-dispatch <dir>       # also runs the interface-dispatch heuristic (needs a buildable module)
go run ./cmd/mcp-server                           # MCP server
```

The RAG pipeline (`rag-pipeline/`, Python/FastAPI) is Phase 2 — scoped, documented in `ARCHITECTURE.md`, not yet built. `scan_file`/`assess_codebase` don't depend on it; `explain_finding`/`suggest_migration` will.

## Architecture

**Go MCP server** (`cmd/mcp-server`, `mcp/`, `internal/`) — long-running Streamable HTTP server at `/mcp`. Static analysis runs entirely in Go, zero external runtime dependency (no subprocess, no cgo) — a deliberate choice; see `internal/scanner`'s history for why tree-sitter-go was evaluated and not adopted (capability tied with `go/ast`, but `go/ast` wins on deployment/contributor friction and MCP-server distribution).

### Shared Core

`internal/scanner/` is imported by both the MCP server and the standalone CLI (`cmd/scan`) — write static analysis logic there, not in `mcp/tools/`. `internal/findings/` defines the `Finding`/`FindingSet`/`CodebaseReport` types shared across entrypoints.

### Detection rules — YAML, not hardcoded Go

Two rule categories, both under `internal/scanner/rules/go/`, both loaded via `go:embed` (still a single self-contained binary — no runtime dependency on finding the YAML on disk, important for `go install`/MCP distribution):

- **`rules/go/direct/*.yaml`** — import-path + function-name allowlists (e.g. `crypto/rsa` → `GenerateKey`/`SignPKCS1v15`/...). An intentional allowlist per package, not "any call into this package" — see `direct/shor.yaml`'s header comment for the reasoning (a curated list is what lets the tool avoid flagging non-actionable calls like `elliptic.Marshal`).
- **`rules/go/interface_dispatch.yaml`** — a heuristic for `crypto.Signer`/`crypto.Decrypter` interface dispatch (calls with no lexical tie to a concrete crypto package, or `crypto.Signer`-typed arguments passed into stdlib sinks like `x509.CreateCertificate`). Needs type information (`go/types`/`go/packages`), so it's opt-in (`scanner.WithInterfaceDispatch()` / `cmd/scan -interface-dispatch`) rather than part of the zero-setup default — it also needs a *buildable* module (resolved deps, Go toolchain), unlike the rest of the scanner.

Adding a new primitive or function means editing YAML, not Go code.

### Confidence

Every `Finding` carries a `Confidence` (`direct` | `heuristic`), orthogonal to `Severity`: `Severity` is "how bad if true", `Confidence` is "how sure we are this is actually happening". A heuristic (interface-dispatch) finding is tagged with `Detail` explaining the attribution reasoning — don't treat it with the same certainty as a direct call.

### RAG — retrieval only, no LLM call, and no separate service either

`internal/explain` (backing `explain_finding`/`suggest_migration`) never calls an LLM. It retrieves grounded chunks and returns `{ finding, chunks, instructions }` — the *calling* model (the MCP host's own LLM, already in the conversation) writes the actual explanation/migration plan from that returned context. Deliberate: no API key needed, it's the native MCP pattern (tools return context, the host reasons over it), and it keeps the Go side to retrieval + formatting — no prompt-engineering/generation code here. See `internal/explain`'s package doc.

Retrieval itself has no separate service either — no Qdrant, no FastAPI, no Docker, no runtime Python. `internal/rag` (planned, not yet built — currently `internal/explain` still calls `ragclient`'s HTTP stub) will be an in-process Go package doing cosine similarity over a precomputed flat-file index, pure Go, no cgo. This works because `explain_finding`/`suggest_migration`'s queries are always exactly `(primitive, usage)` — a small bounded set, not free text — so query embeddings can be precomputed offline alongside the corpus chunk embeddings. Runtime needs zero ML inference, just array lookup and arithmetic. See `ARCHITECTURE.md`'s "Retrieval" section for the full design and why a vector database turned out to be disproportionate to this corpus's actual size.

Python survives only as offline, maintainer-run ingestion tooling (`rag-pipeline/ingest/`) — PDF parsing + embedding, run rarely (corpus changes rarely), never shipped to end users. Corpus will live in `rag-pipeline/corpus/`: FIPS 203/204/205 PDFs, CNSA 2.0, RFC 9180, and hand-authored migration playbooks (curated RSA→ML-KEM, ECDH→ML-KEM, ECDSA→ML-DSA migration guides, each tagged with a `<usage>_migration` key matching what `suggest_migration` queries for) — the primary differentiation once built.

`Finding.Context` — argument source text (via `go/printer`, not restricted to literals) + enclosing function/file, extracted by the same AST walk already visiting each call site (`internal/scanner/context_go.go`, shared by the direct-call and interface-dispatch paths). Threaded through `mcp/tools.FindingParams` into `internal/explain`'s `Instructions` text as extra grounding — e.g. "inside `useRSA()`, called with `rand.Reader, 2048`". Deliberately does *not* include call-graph/reachability info — considered and deferred, see `ARCHITECTURE.md`'s "Future Enhancements".

## Current State

Go scanner is functional: direct-call detection (RSA/ECDSA/ECDH/ECC, Shor-broken only) plus an opt-in interface-dispatch heuristic, both YAML-rule-driven. Validated against multiple real-world Go repos (see `internal/scanner`'s design notes / commit history for specifics). RAG pipeline is Phase 2, not started. `go build ./...` builds clean across the whole repo, including `mcp/tools`/`cmd/mcp-server` (a `go.sum` gap that existed earlier was fixed via `go mod tidy`).

Known, deliberately out-of-scope gaps (tracked, not forgotten): `crypto/ed25519`, `golang.org/x/crypto/curve25519`, `golang.org/x/crypto/ssh`, and the `tls.Certificate.PrivateKey` struct-field pattern (a third interface-dispatch rule `kind` the current schema doesn't have yet).
