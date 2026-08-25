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

// Out of scope (documented limitation, needs --deep mode / type info):
// the concrete RSA implementation is supplied by the caller through the
// stdlib crypto.Signer interface, so this file has no lexical tie to
// crypto/rsa at all.
func useSigner(s crypto.Signer, digest []byte) {
	s.Sign(rand.Reader, digest, nil)
}
