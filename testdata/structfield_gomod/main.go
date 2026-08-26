// Fixture for two interface-dispatch rule kinds that don't fit the
// receiver/argument shapes already covered by testdata/indirect_gomod:
// struct_field (crypto/tls.Certificate.PrivateKey) and an argument-kind
// rule matched against a method on an arbitrary local receiver
// (crypto/x509.Certificate.CreateCRL), both stdlib-only so this fixture
// needs no network access to build.
package structfield

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

// Resolvable by the default (zero-setup) scan — makes RSA "present" in this
// module, the precondition every interface-dispatch finding below needs.
func makeKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

// Invisible to the default scan: crypto/tls.Certificate.PrivateKey is a
// struct field, not a function call. Resolved only by the struct_field
// interface-dispatch rule kind.
func buildCert(key *rsa.PrivateKey) tls.Certificate {
	return tls.Certificate{PrivateKey: key}
}

// Invisible to the default scan, same reasoning as
// testdata/indirect_gomod's useSigner: the concrete RSA implementation
// reaches CreateCRL only through the stdlib crypto.Signer interface.
// CreateCRL is also a method on an arbitrary local receiver
// (*x509.Certificate), not a package-level function — confirms the
// argument-kind rule's `func:` matching resolves methods the same way.
func signCRL(cert *x509.Certificate, signer crypto.Signer) {
	cert.CreateCRL(rand.Reader, signer, []pkix.RevokedCertificate{}, time.Now(), time.Now())
}
