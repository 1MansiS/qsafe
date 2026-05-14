# qsafe — Architecture & Build Plan

> **PQC Migration Advisor**: A static analysis tool that scans codebases for
> classical cryptographic primitives and uses RAG over NIST PQC standards to
> generate concrete, spec-grounded migration guidance — exposed as an MCP server
> for AI assistant integration.

---

## Project Identity

| Field | Value |
|---|---|
| Name | `qsafe` |
| Binary | `qsafe` (v2) |
| Module path | `github.com/1MansiS/qsafe` |
| MCP server image | `ghcr.io/1mansis/qsafe-mcp` |
| License | Apache 2.0 |

---

## Design Principles

1. **MCP-first, CLI is v2.** The primary interface is an MCP server consumed by Claude, Cursor, or any MCP-compatible host. CLI comes later.
2. **RAG is an implementation detail.** MCP clients see only tool results. The RAG pipeline is internal to the server — swappable without changing the MCP interface.
3. **Shared core.** Static analysis logic lives in `internal/scanner/` — imported by both the MCP server (v1) and CLI (v2). Written once.
4. **Clean Go ↔ Python boundary.** The MCP server (Go) calls the RAG service (Python/FastAPI) over a local HTTP API. The interface is stable; implementations are swappable.
5. **Docker-first distribution.** Users run one `docker-compose up` or one `docker run`. Zero Go/Python setup required.

---

## Repository Structure (Monorepo)

```
qsafe/
├── cmd/
│   ├── mcp-server/         # MCP server entrypoint (v1)
│   └── qsafe/              # CLI entrypoint (v2, placeholder)
│
├── internal/
│   ├── scanner/            # Core static analysis engine
│   │   ├── ast.go          # tree-sitter AST parsing
│   │   ├── semgrep.go      # Semgrep rule runner
│   │   ├── findings.go     # Finding types, deduplication
│   │   └── severity.go     # Severity scoring logic
│   ├── findings/           # Shared finding data model
│   └── ragclient/          # HTTP client → Python RAG service
│
├── mcp/
│   ├── server.go           # MCP server setup, tool registration
│   └── tools/
│       ├── scan_file.go
│       ├── explain_finding.go
│       ├── suggest_migration.go
│       └── assess_codebase.go
│
├── rag-pipeline/           # Python RAG service
│   ├── ingest/             # Document chunking + embedding pipeline
│   │   ├── chunker.py      # Section-aware chunking
│   │   ├── embedder.py     # Embedding model wrapper
│   │   └── loader.py       # PDF/text corpus loader
│   ├── retrieval/          # Query + reranking logic
│   │   ├── query.py        # Hybrid retrieval (dense + BM25)
│   │   └── reranker.py     # Cross-encoder reranking
│   ├── api/                # FastAPI service
│   │   └── main.py         # POST /retrieve endpoint
│   └── corpus/             # Source documents (tracked in git)
│       ├── fips-203.pdf    # ML-KEM
│       ├── fips-204.pdf    # ML-DSA
│       ├── fips-205.pdf    # SLH-DSA
│       ├── cnsa-2.0.pdf    # NSA migration requirements
│       └── annotations/    # Mansi's hand-authored migration playbooks
│           ├── rsa-to-mlkem.md
│           ├── ecdh-to-mlkem.md
│           └── ecdsa-to-mldsa.md
│
├── rules/                  # Semgrep YAML rules for crypto detection
│   ├── java/
│   ├── python/
│   ├── go/
│   └── c/
│
├── docker/
│   ├── Dockerfile.mcp-server
│   └── Dockerfile.rag
│
├── docker-compose.yml      # Orchestrates: Qdrant + RAG service + MCP server
├── .mcp.json.example       # Drop-in config for Claude/Cursor users
├── ARCHITECTURE.md         # This file
└── README.md
```

---

## Component Overview

### 1. MCP Server (Go)

**What it is:** A long-running Streamable HTTP server at `/mcp` that exposes
four tools to any MCP-compatible LLM host.

**Stack:** Go, `modelcontextprotocol/go-sdk`, `smacker/go-tree-sitter`

**Tools exposed:**

| Tool | Mechanism | Uses RAG? |
|---|---|---|
| `scan_file` | AST parsing + Semgrep rules | No — pure static analysis |
| `explain_finding` | LLM generation | Yes — RAG grounds explanation |
| `suggest_migration` | LLM generation | Yes — RAG provides spec-accurate code |
| `assess_codebase` | Aggregation + scoring | Partially — RAG for compliance mapping |

**Tool details:**

`scan_file(path: string) → FindingSet`
- Runs tree-sitter AST analysis to detect classical primitives
- Runs Semgrep rules over the target path
- Returns structured `FindingSet`: `[{ primitive, usage, file, line, severity }]`
- No RAG involved — pure deterministic analysis

`explain_finding(finding: Finding) → Explanation`
- Calls RAG service: `POST /retrieve { primitive, usage, top_k: 5 }`
- Receives top-k chunks from FIPS/CNSA/annotation corpus
- Injects chunks into LLM prompt as grounding context
- Returns: why it's quantum-vulnerable, timeline, which NIST standard applies

`suggest_migration(finding: Finding) → MigrationPlan`
- Calls RAG service with code-oriented query
- Returns: recommended replacement, migration path, library, before/after code,
  hybrid-mode caveat (classical + PQC in parallel during transition)

`assess_codebase(path: string) → CryptoInventoryReport`
- Calls `scan_file` across all files in path
- Aggregates findings into a CBOM (Cryptography Bill of Materials)
- Produces prioritized migration roadmap
- Maps findings to CNSA 2.0 compliance gaps

---

### 2. RAG Pipeline (Python)

**What it is:** An internal FastAPI service — not user-facing. Called by the
MCP server over a local HTTP endpoint.

**Stack:** Python, FastAPI, LlamaIndex, Qdrant, OpenAI embeddings + BM25

**Corpus:**

| Document | Coverage |
|---|---|
| FIPS 203 (ML-KEM) | Primary KEM replacement spec |
| FIPS 204 (ML-DSA) | Signature replacement |
| FIPS 205 (SLH-DSA) | Hash-based signature alternative |
| CNSA 2.0 Suite | NSA migration timeline requirements |
| RFC 9180 (HPKE) | Hybrid public key encryption |
| Hand-authored annotations | Curated migration playbooks per primitive |

**Chunking strategy:**
- Section-aware: chunk at heading boundaries, preserve hierarchy in metadata
- Metadata per chunk: `primitive_type`, `operation`, `security_level`, `source`
- Algorithm definitions chunked with surrounding context preserved

**Retrieval flow:**
```
Query (primitive + usage context)
    ↓
Hybrid retrieval:
    Dense:  embedding similarity (text-embedding-3-small)
    Sparse: BM25 over algorithm identifiers, RFC numbers, FIPS references
    → Cross-encoder reranking
    → Metadata filter: { primitive_type, operation }
    ↓
Top-k chunks → returned to MCP server → injected into LLM prompt
```

**API surface (internal only):**
```
POST /retrieve
{
  "primitive": "RSA-2048",
  "usage":     "key_exchange",
  "top_k":     5
}

→ [{ text, source, section, score }]
```

**Update cadence:** Static corpus with manual refresh. NIST FIPS standards
change rarely. Rebuild index when a new standard is finalized (~annually).

---

### 3. Infrastructure

**Qdrant:** Vector store for embeddings. Runs as a Docker container.
Local for development; can be swapped for Qdrant Cloud for production.

**docker-compose.yml** orchestrates three services:
```
services:
  qdrant:        # vector store
  rag-service:   # Python FastAPI RAG pipeline
  mcp-server:    # Go MCP server
```

**User setup (MCP persona):**
```bash
docker-compose up
```

Then in `.mcp.json`:
```json
{
  "mcpServers": {
    "qsafe": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

---

## Data Flow (Runtime)

```
Claude / Cursor (MCP client)
    │
    │  "scan this file and explain the findings"
    ▼
qsafe MCP Server (Go, :8080)
    │
    ├─► scan_file
    │       └─► tree-sitter AST + Semgrep rules
    │           returns: FindingSet
    │
    ├─► explain_finding (for each finding)
    │       └─► POST /retrieve → RAG service (:8000)
    │               └─► Qdrant → top-k chunks
    │           chunks injected into LLM prompt
    │           returns: grounded explanation
    │
    └─► suggest_migration
            └─► POST /retrieve → RAG service (:8000)
                chunks + code context → LLM prompt
                returns: migration plan + code snippet
```

---

## Phased Build Plan

### Phase 0 — Foundations (Week 1)
*Goal: repo skeleton, toolchain verified, nothing broken.*

- [ ] Initialize monorepo: `go mod init github.com/1MansiS/qsafe`
- [ ] Scaffold directory structure (all dirs, empty `.go` and `.py` stubs)
- [ ] Confirm `modelcontextprotocol/go-sdk` compiles; write a hello-world MCP
      server that returns a hardcoded string
- [ ] `docker-compose.yml` with Qdrant only; verify Qdrant is reachable
- [ ] `rag-pipeline/api/main.py`: stub FastAPI with `/health` and `/retrieve`
      returning hardcoded chunks
- [ ] Wire Go MCP server → stub RAG service over HTTP; confirm round-trip
- [ ] Deliverable: MCP server registers one tool (`ping`), calls RAG stub,
      returns response. Visible in MCP Inspector.

---

### Phase 1 — Static Analysis Engine (Weeks 2–3)
*Goal: `scan_file` works end-to-end. No RAG yet.*

- [ ] Integrate `smacker/go-tree-sitter` for Go, Python, Java, C
- [ ] Write AST visitors that detect:
  - RSA (key generation, encryption, signing)
  - ECDH / ECDSA (key agreement, signing)
  - AES-ECB, 3DES, RC4, DES
  - MD5, SHA-1 in signature contexts
  - Key sizes below threshold (RSA < 3072, ECC < 256-bit)
- [ ] Write Semgrep YAML rules for same primitives (Java + Python first,
      highest-value languages from Veracode experience)
- [ ] Implement `findings.go`: deduplication, severity scoring
- [ ] Register `scan_file` as MCP tool; test against synthetic vulnerable repos
- [ ] Deliverable: `scan_file` returns real findings in Claude. Demo-able.

---

### Phase 2 — RAG Pipeline (Weeks 4–5)
*Goal: `/retrieve` returns real grounded chunks from FIPS corpus.*

- [ ] Collect corpus: download FIPS 203/204/205, CNSA 2.0, RFC 9180
- [ ] Write `ingest/chunker.py`: section-aware chunking with metadata tagging
- [ ] Write `ingest/embedder.py`: embed chunks with `text-embedding-3-small`,
      upsert into Qdrant
- [ ] Write first-pass migration annotations for top 5 primitives:
  - RSA → ML-KEM (key exchange)
  - ECDH → ML-KEM (key agreement)
  - ECDSA → ML-DSA (signatures)
  - RSA-PSS → ML-DSA
  - 3DES → AES-256-GCM (symmetric, not PQC but required cleanup)
- [ ] Run ingestion pipeline; verify chunks in Qdrant
- [ ] Implement `retrieval/query.py`: dense retrieval + BM25 hybrid
- [ ] Wire `/retrieve` to real Qdrant; test query quality manually
- [ ] Deliverable: `/retrieve` returns relevant FIPS chunks for 5 test queries.

---

### Phase 3 — Explain & Migrate Tools (Week 6)
*Goal: `explain_finding` and `suggest_migration` work end-to-end with real RAG.*

- [ ] Implement `explain_finding` MCP tool in Go:
  - Calls `/retrieve` with finding context
  - Builds grounded prompt (context + finding + instruction)
  - Returns explanation with source citations
- [ ] Implement `suggest_migration` MCP tool:
  - Code-oriented RAG query
  - Prompt includes before-snippet from scan result
  - Returns: replacement algorithm, library, before/after code, hybrid-mode note
- [ ] Add cross-encoder reranking to `retrieval/reranker.py`
- [ ] Prompt engineering: iterate on explanation and migration prompts
- [ ] Deliverable: Full demo — scan a Java file with RSA, explain it, get
      migration plan to ML-KEM-768 with liboqs code snippet.

---

### Phase 4 — `assess_codebase` + CBOM (Week 7)
*Goal: repo-level analysis with prioritized output.*

- [ ] Implement `assess_codebase`: walk repo, call `scan_file` per file,
      aggregate `FindingSet`
- [ ] Implement severity × exploitability × migration-complexity scoring
- [ ] CNSA 2.0 compliance gap mapping
- [ ] Output: Crypto Bill of Materials (CBOM) — prioritized finding list +
      migration roadmap
- [ ] SARIF output format (foundation for future CI/CD integration)
- [ ] Deliverable: `assess_codebase` on a real OSS repo produces a meaningful
      CBOM report in Claude.

---

### Phase 5 — Hardening + OSS Launch (Week 8)
*Goal: project is demo-able, documented, and ready for public GitHub.*

- [ ] `Dockerfile.mcp-server` and `Dockerfile.rag`: multi-stage builds,
      minimal images
- [ ] `docker-compose.yml`: production-ready, health checks, restart policies
- [ ] `.mcp.json.example`: copy-paste config for Claude and Cursor users
- [ ] `README.md`: clear setup in under 5 minutes, demo GIF/video
- [ ] MCP Inspector test pass: all four tools exercise correctly
- [ ] Test against 3 real OSS repos (mixed Java/Python/Go)
- [ ] GitHub Actions CI: lint, test, build Docker image on push
- [ ] Publish `ghcr.io/1mansis/qsafe-mcp` image
- [ ] Deliverable: Public repo, working Docker image, demo video.

---

### Phase 6 — CLI (v2, Future)
*Deferred. Core logic already lives in `internal/scanner/` — CLI is a thin
wrapper.*

- [ ] `cmd/qsafe/main.go`: Cobra CLI with `scan`, `explain`, `assess` subcommands
- [ ] SARIF output for GitHub Code Scanning integration
- [ ] GitHub Actions workflow example: `qsafe assess` as a CI step
- [ ] Homebrew tap / `go install` distribution

---

## Tech Stack Summary

| Layer | Technology | Rationale |
|---|---|---|
| MCP server | Go, `modelcontextprotocol/go-sdk` | Single binary, Docker-friendly, existing VulnCheck pattern |
| AST analysis | `smacker/go-tree-sitter` | Multi-language, Go-native, production-grade |
| Semgrep rules | YAML | Declarative, community-compatible, language-aware AST matching |
| RAG service | Python, FastAPI | ML ecosystem maturity; Qdrant/LlamaIndex are Python-native |
| Embeddings | `text-embedding-3-small` (OpenAI) | Quality/cost balance for a bounded technical corpus |
| Vector store | Qdrant | Strong hybrid search (dense + sparse), good Go + Python clients |
| Reranking | Cross-encoder (sentence-transformers) | Improves retrieval precision on technical spec language |
| Orchestration | docker-compose | Zero-setup for OSS users |

---

## Key Architectural Decisions

**Why MCP-first, not CLI-first?**
MCP is the differentiating component — it's what makes this an AI × security
project rather than another SAST linter. The agentic multi-tool chaining
(scan → explain → migrate in one conversation turn) is only possible via MCP.

**Why Go + Python split?**
Go for the MCP server: single binary, clean Docker distribution, existing
`modelcontextprotocol/go-sdk` familiarity. Python for RAG: LlamaIndex, Qdrant
client, and embedding models are Python-native. Fighting the Go ML ecosystem
would waste weeks.

**Why Qdrant over Pinecone/Weaviate?**
Local Docker deployment for OSS users. No API key required to run `qsafe`.
Qdrant's hybrid search (dense + sparse) is a first-class feature, not a bolt-on.

**Why hybrid retrieval (dense + BM25)?**
Algorithm names like `ML-KEM-768`, `FIPS 203`, `RFC 9180` are exact tokens
that embedding similarity handles poorly. BM25 catches exact matches; dense
retrieval catches semantic similarity. Both are needed.

**Why section-aware chunking?**
Naive fixed-size chunking splits algorithm definitions mid-spec, producing
useless retrieved chunks. Section boundaries in NIST documents align with
algorithm units — chunking there preserves the coherent unit of knowledge.

**Why hand-authored migration annotations?**
No public document has "RSA-2048 KEM → ML-KEM-768 via oqs-provider" in one
place. These playbooks encode domain expertise (SandboxAQ PQC + Veracode SAST
background) that no public corpus has. This is the primary moat of the project.
