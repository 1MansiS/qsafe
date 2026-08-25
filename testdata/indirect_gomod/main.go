// Fixture for one-hop function-value indirection: a package-level var
// holds a crypto function value directly (no call), and is invoked later
// under a different name than the crypto package selector.
package indirect

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// Resolvable: bare function value assigned to a var, then called through it.
var keyGen = rsa.GenerateKey

func wrapper() {
	keyGen(rand.Reader, 2048)
}

// Invisible to the default (zero-setup) scan — the concrete RSA
// implementation is supplied by the caller through the stdlib crypto.Signer
// interface, so this file has no lexical tie to crypto/rsa at all. Resolved
// only by the opt-in interface-dispatch heuristic
// (scanner.WithInterfaceDispatch / cmd/scan -interface-dispatch) — see
// TestScanDir_Go_InterfaceDispatch, which uses this exact function.
func useSigner(s crypto.Signer, digest []byte) {
	s.Sign(rand.Reader, digest, nil)
}
