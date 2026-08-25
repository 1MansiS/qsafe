// Fixture reproducing a code-review follow-up: the first scope-isolation
// fix (see testdata/scoped_indirect_gomod) scoped shadowing to the
// *enclosing function*, not the enclosing *block* — so a block-local shadow
// incorrectly blocked resolution for the rest of the function too, not just
// within its own block. Verified failing (0 findings, should be 1) before
// the block-scope-chain fix landed.
package blockscope

import (
	"crypto/rand"
	"crypto/rsa"
)

var keyGen = rsa.GenerateKey

// f's if-block locally shadows keyGen with an unrelated function — that
// must only block resolution *within the block*. The call after the
// block, back at function scope, must still resolve to the package-level
// RSA binding.
func f(cond bool) {
	if cond {
		keyGen := add
		keyGen(1, 2) // shadowed within this block — must not be flagged
	}
	keyGen(rand.Reader, 2048) // package-level RSA — must be flagged
}

func add(a, b int) int { return a + b }
