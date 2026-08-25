// Package explain implements explain_finding and suggest_migration's core
// logic: retrieval only, no LLM call. qsafe never generates prose itself —
// it retrieves grounded FIPS/CNSA/annotation chunks and returns them
// alongside instructions for the *calling* model (the MCP host's own LLM,
// already in the conversation) to write the actual explanation, citing
// sources. This is a deliberate design choice, not a placeholder for a
// future LLM-calling implementation:
//
//   - No API key, ever — consistent with every other zero-setup design
//     choice in this project (local Qdrant, local embeddings, no cgo).
//   - The native MCP pattern: tools return structured context for the
//     host's own model to reason over, not run a second, independent
//     generation pipeline that duplicates capability the host already has.
//   - Simpler: this package is retrieval + formatting, no prompt
//     engineering or generation orchestration.
package explain

import (
	"context"
	"fmt"
	"strings"

	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/ragclient"
)

// Result is returned by both Explain and SuggestMigration — same shape,
// different Instructions and a different (usage-scoped) retrieval query.
// The Finding is echoed back so the calling model doesn't have to
// cross-reference it separately.
type Result struct {
	Finding      findings.Finding  `json:"finding"`
	Chunks       []ragclient.Chunk `json:"chunks"`
	Instructions string            `json:"instructions"`
}

// Explain retrieves grounding context for why f is quantum-vulnerable.
func Explain(ctx context.Context, rag *ragclient.Client, f findings.Finding) (*Result, error) {
	chunks, err := rag.Retrieve(ctx, ragclient.RetrieveRequest{
		Primitive: f.Primitive,
		Usage:     f.Usage,
		TopK:      5,
	})
	if err != nil {
		return nil, fmt.Errorf("retrieve: %w", err)
	}
	return &Result{
		Finding: f,
		Chunks:  chunks,
		Instructions: fmt.Sprintf(
			"Using the cited FIPS/CNSA excerpts above, explain why this %s %s call (%s:%d)%s is quantum-vulnerable — which NIST standard applies, and the Harvest-Now-Decrypt-Later timeline relevance. Cite the specific document and section for each claim; don't assert anything the excerpts don't support.",
			f.Primitive, f.Usage, f.File, f.Line, contextClause(f)),
	}, nil
}

// contextClause renders f.Context, if present, as a short parenthetical to
// fold into an Instructions sentence — e.g. " (inside useRSA(), called with
// rand.Reader, 2048)". Empty string when there's nothing to add, so callers
// can splice it in without a separate conditional.
func contextClause(f findings.Finding) string {
	if f.Context == nil {
		return ""
	}
	var parts []string
	if fn := f.Context.Function; fn != "" {
		if f.Context.InTest {
			parts = append(parts, fmt.Sprintf("inside %s() in a test file", fn))
		} else {
			parts = append(parts, fmt.Sprintf("inside %s()", fn))
		}
	} else if f.Context.InTest {
		parts = append(parts, "in a test file")
	}
	if len(f.Context.Arguments) > 0 {
		parts = append(parts, "called with "+strings.Join(f.Context.Arguments, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// SuggestMigration retrieves grounding context for how to migrate f —
// same shape as Explain, but the retrieval query is usage-scoped toward
// migration-oriented content (the hand-authored annotation playbooks are
// written to match this), and the instructions ask for a concrete
// before/after code change rather than an explanation.
func SuggestMigration(ctx context.Context, rag *ragclient.Client, f findings.Finding) (*Result, error) {
	chunks, err := rag.Retrieve(ctx, ragclient.RetrieveRequest{
		Primitive: f.Primitive,
		Usage:     f.Usage + "_migration",
		TopK:      5,
	})
	if err != nil {
		return nil, fmt.Errorf("retrieve: %w", err)
	}
	return &Result{
		Finding: f,
		Chunks:  chunks,
		Instructions: fmt.Sprintf(
			"Using the cited migration playbooks above, propose a concrete before/after code change replacing this %s %s usage (%s:%d)%s with its NIST PQC equivalent — recommended algorithm, replacement library, and any hybrid-mode caveat (classical + PQC in parallel during transition) mentioned in the sources.",
			f.Primitive, f.Usage, f.File, f.Line, contextClause(f)),
	}, nil
}
