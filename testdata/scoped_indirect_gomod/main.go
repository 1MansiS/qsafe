// Fixture reproducing the scope-unaware indirection false positive found
// by code review: a package-level `keyGen` bound to rsa.GenerateKey must
// not cause an unrelated *local* `keyGen` (shadowing the name, bound to a
// completely unrelated function) in a different function to also be
// flagged as RSA.
package scopedindirect

import (
	"crypto/rand"
	"crypto/rsa"
)

var keyGen = rsa.GenerateKey

// useCrypto calls the real, package-level keyGen — should be flagged RSA.
func useCrypto() {
	keyGen(rand.Reader, 2048)
}

// unrelated shadows keyGen locally with an unrelated function value — must
// NOT be flagged, even though the name matches.
func unrelated() {
	keyGen := add
	keyGen(1, 2)
}

func add(a, b int) int { return a + b }
