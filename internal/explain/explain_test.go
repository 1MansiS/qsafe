package explain_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1MansiS/qsafe/internal/explain"
	"github.com/1MansiS/qsafe/internal/findings"
	"github.com/1MansiS/qsafe/internal/ragclient"
)

// stubRAG records the request it received and returns one fixed chunk —
// enough to verify Explain/SuggestMigration query the right (primitive,
// usage) and never touch an LLM themselves, just retrieval + formatting.
func stubRAG(t *testing.T) (*httptest.Server, *ragclient.RetrieveRequest) {
	t.Helper()
	var got ragclient.RetrieveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode([]ragclient.Chunk{
			{Text: "RSA relies on integer factorization...", Source: "fips-203.pdf", Section: "1.1", Score: 0.9},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestExplain_QueriesFindingPrimitiveAndUsage(t *testing.T) {
	srv, got := stubRAG(t)
	rag := ragclient.New(srv.URL)

	f := findings.Finding{Primitive: "RSA", Usage: "key_generation", File: "server/tls.go", Line: 42}
	result, err := explain.Explain(context.Background(), rag, f)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}

	if got.Primitive != "RSA" || got.Usage != "key_generation" {
		t.Errorf("expected retrieval query for RSA/key_generation, got %+v", got)
	}
	if len(result.Chunks) != 1 {
		t.Fatalf("expected the stub's 1 chunk passed through, got %v", result.Chunks)
	}
	if result.Finding != f {
		t.Errorf("expected the finding echoed back unchanged, got %+v", result.Finding)
	}
	// The whole point of this design: qsafe never writes the explanation
	// itself — Instructions must direct the calling model to do it,
	// grounded in the returned chunks.
	if !strings.Contains(result.Instructions, "explain why") {
		t.Errorf("expected Instructions to direct the calling model to explain, got %q", result.Instructions)
	}
}

func TestExplain_FoldsContextIntoInstructions(t *testing.T) {
	srv, _ := stubRAG(t)
	rag := ragclient.New(srv.URL)

	f := findings.Finding{
		Primitive: "RSA", Usage: "key_generation", File: "server/tls.go", Line: 42,
		Context: &findings.Context{Function: "useRSA", Arguments: []string{"rand.Reader", "2048"}},
	}
	result, err := explain.Explain(context.Background(), rag, f)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	for _, want := range []string{"useRSA()", "rand.Reader, 2048"} {
		if !strings.Contains(result.Instructions, want) {
			t.Errorf("expected Instructions to mention %q, got %q", want, result.Instructions)
		}
	}
}

func TestExplain_NoContext_NoStrayText(t *testing.T) {
	srv, _ := stubRAG(t)
	rag := ragclient.New(srv.URL)

	f := findings.Finding{Primitive: "RSA", Usage: "key_generation", File: "server/tls.go", Line: 42}
	result, err := explain.Explain(context.Background(), rag, f)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if strings.Contains(result.Instructions, "()") || strings.Contains(result.Instructions, "  ") {
		t.Errorf("expected no context artifacts when Context is nil, got %q", result.Instructions)
	}
}

func TestSuggestMigration_ScopesQueryToMigrationUsage(t *testing.T) {
	srv, got := stubRAG(t)
	rag := ragclient.New(srv.URL)

	f := findings.Finding{Primitive: "ECDSA", Usage: "signing", File: "auth/sign.go", Line: 10}
	result, err := explain.SuggestMigration(context.Background(), rag, f)
	if err != nil {
		t.Fatalf("SuggestMigration: %v", err)
	}

	// Migration-oriented content is retrieved under a distinct usage key
	// (see rules/go's annotation playbooks) so it doesn't collide with
	// explain_finding's plain "signing" query.
	if got.Usage != "signing_migration" {
		t.Errorf("expected usage query scoped to migration content, got %q", got.Usage)
	}
	if !strings.Contains(result.Instructions, "before/after code change") {
		t.Errorf("expected Instructions to ask for a concrete code change, got %q", result.Instructions)
	}
}
