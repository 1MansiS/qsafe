package findings

import (
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Confidence is orthogonal to Severity: Severity is "how bad if true",
// Confidence is "how sure we are this is actually happening". A heuristic
// finding (e.g. interface-dispatch attribution — see
// internal/scanner/callgraph_go.go's package doc) can be just as severe as
// a direct one; it just shouldn't be asserted with the same certainty.
//
// Set explicitly by every producer, never left to the Go zero-value. Only
// Go is scanned today (see qsafe.md's "design for uniformity, build for Go
// only" note) — if/when another language's scanner is added, it must set
// this explicitly too, not rely on the zero-value defaulting to anything
// meaningful.
type Confidence string

const (
	ConfidenceDirect    Confidence = "direct"    // e.g. rsa.GenerateKey(...) — unambiguous
	ConfidenceHeuristic Confidence = "heuristic" // e.g. interface dispatch — attributed, not proven
)

// Context is per-call-site information the same AST walk that produced the
// Finding was already visiting — no new analysis tier, no call-graph
// traversal. Arguments is the source text of every call argument, in call
// order (via go/printer, not restricted to literals — a plain identifier
// like a variable name is still useful grounding, and picking apart "which
// argument is the meaningful one" would need per-function-signature
// knowledge, the same kind of hardcoded-in-Go primitive knowledge this
// project has deliberately kept out of the scanner in favor of YAML rules).
// Deliberately does NOT include caller/reachability information (who calls
// this, what's downstream) — that's a different, much more expensive class
// of analysis, considered and deferred; see ARCHITECTURE.md's "Future
// Enhancements".
type Context struct {
	Function  string   `json:"function,omitempty"`
	InTest    bool     `json:"in_test,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
}

// String renders c as a short human-readable clause, e.g. "in useRSA(),
// args: rand.Reader, 2048" — shared by every text-formatting call site
// (cmd/scan, mcp/tools) so there's one place that defines what this looks
// like, not a copy per caller.
func (c *Context) String() string {
	if c == nil {
		return ""
	}
	var parts []string
	if c.Function != "" {
		if c.InTest {
			parts = append(parts, fmt.Sprintf("in %s() (test file)", c.Function))
		} else {
			parts = append(parts, fmt.Sprintf("in %s()", c.Function))
		}
	} else if c.InTest {
		parts = append(parts, "(test file)")
	}
	if len(c.Arguments) > 0 {
		parts = append(parts, "args: "+strings.Join(c.Arguments, ", "))
	}
	return strings.Join(parts, ", ")
}

type Finding struct {
	Primitive  string     `json:"primitive"`
	Usage      string     `json:"usage"`
	File       string     `json:"file"`
	Line       int        `json:"line"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Context    *Context   `json:"context,omitempty"`
}

type FindingSet struct {
	Findings []Finding `json:"findings"`
}

type CodebaseReport struct {
	Root              string         `json:"root"`
	FilesScanned      int            `json:"files_scanned"`
	FilesWithFindings int            `json:"files_with_findings"`
	ByPrimitive       map[string]int `json:"by_primitive"`
	Findings          []Finding      `json:"findings"`
}
