package scanner

import "testing"

// TestParseInterfaceRules_MalformedYAML_ReturnsError_NotPanic is a
// regression test for a code-review finding: rule loading used to panic
// (in a package-level var initializer, run unconditionally at package
// init) on malformed YAML, which would crash every scan — including plain
// default ones that never opt into WithInterfaceDispatch. Now it's a
// regular error, returned only from the opt-in code path
// (scanGoModuleInterfaceDispatch), lazily on first real use.
func TestParseInterfaceRules_MalformedYAML_ReturnsError_NotPanic(t *testing.T) {
	_, err := parseInterfaceRules([]byte("not: valid: yaml: at: all: - ["))
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
}

func TestParseInterfaceRules_ValidYAML(t *testing.T) {
	rules, err := parseInterfaceRules([]byte(`
- kind: receiver
  interface_package: crypto
  interface_name: Signer
  method: Sign
  usage: signing
  implementers: [RSA]
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 || rules[0].Method != "Sign" {
		t.Errorf("expected one parsed rule with Method=Sign, got: %+v", rules)
	}
}
