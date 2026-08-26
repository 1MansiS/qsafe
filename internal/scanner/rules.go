package scanner

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/1MansiS/qsafe/internal/findings"
)

// rules/go/direct/*.yaml only — kept in its own subdirectory, separate
// from rules/go/interface_dispatch.yaml (a different schema, loaded by
// interface_dispatch_go.go), so the two embeds/globs can't collide and
// silently try to parse one schema as the other.
//
//go:embed rules/go/direct/*.yaml
var goRulesFS embed.FS

// goRule is one YAML entry: an import path, the primitive it represents,
// and an intentional allowlist of functions worth flagging (not "every
// call into this package") — see rules/go/direct/shor.yaml's header
// comment for why the allowlist is curated rather than blanket.
type goRule struct {
	Primitive string            `yaml:"primitive"`
	Import    string            `yaml:"import"`
	Category  string            `yaml:"category"`
	Severity  string            `yaml:"severity"`
	Functions map[string]string `yaml:"functions"`
}

// loaded once at package init from the embedded YAML, indexed by import
// path for O(1) lookup during the AST walk. A slice per import, not a
// single rule, because one package can hold functions for more than one
// primitive — e.g. crypto/x509.ParsePKCS1PrivateKey is unambiguously RSA
// (PKCS1 is an RSA-only format) while crypto/x509.ParseECPrivateKey is
// unambiguously ECDSA (SEC1 EC format), both in the same package. A single
// self-contained binary still results — go:embed compiles the rule files
// in, no runtime dependency on finding them on disk (important for
// `go install`/MCP server distribution, where the binary may end up far
// from its source tree).
var goRulesByImport = mustLoadGoRules()

func mustLoadGoRules() map[string][]goRule {
	rules, err := loadGoRules(goRulesFS)
	if err != nil {
		// Embedded, author-controlled config — a load failure here is a
		// build-time mistake, not a runtime condition callers should
		// have to handle everywhere goCryptoTargets used to be read.
		panic(fmt.Sprintf("scanner: invalid embedded Go rules: %v", err))
	}
	return rules
}

func loadGoRules(fsys embed.FS) (map[string][]goRule, error) {
	matches, err := fsys.ReadDir("rules/go/direct")
	if err != nil {
		return nil, err
	}

	byImport := make(map[string][]goRule)
	for _, entry := range matches {
		data, err := fsys.ReadFile("rules/go/direct/" + entry.Name())
		if err != nil {
			return nil, err
		}
		var rules []goRule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		for _, r := range rules {
			if r.Import == "" || r.Primitive == "" {
				return nil, fmt.Errorf("%s: rule missing import or primitive: %+v", entry.Name(), r)
			}
			if _, ok := severityFromString(r.Severity); !ok {
				return nil, fmt.Errorf("%s: rule %s has invalid severity %q", entry.Name(), r.Primitive, r.Severity)
			}
			byImport[r.Import] = append(byImport[r.Import], r)
		}
	}
	return byImport, nil
}

// findGoRule returns the rule block registered for importPath whose
// Functions allowlist contains fn, trying each block in declaration order
// (there's normally exactly one; see goRulesByImport's doc comment for why
// there can be more).
func findGoRule(importPath, fn string) (goRule, bool) {
	for _, r := range goRulesByImport[importPath] {
		if _, ok := r.Functions[fn]; ok {
			return r, true
		}
	}
	return goRule{}, false
}

func severityFromString(s string) (findings.Severity, bool) {
	switch findings.Severity(s) {
	case findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow:
		return findings.Severity(s), true
	default:
		return "", false
	}
}
