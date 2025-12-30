// Package signer provides the Signer interface for custom JWT signing.
// This allows integration with HSMs, cloud KMS, and other external signing services.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer defines an interface for JWT signing operations.
// Implement this interface to use external signing services like HSMs or cloud KMS.
type Signer interface {
	// Sign signs the JWT content and returns the signature.
	// The signingInput is the JWT content to sign: base64url(header) + "." + base64url(payload)
	// Returns the raw signature bytes (which will be base64url encoded by the caller).
	Sign(signingInput string) ([]byte, error)

	// Algorithm returns the JWT "alg" header value (e.g., "ES256", "RS256", "EdDSA").
	Algorithm() string

	// PublicKey returns the public key corresponding to the signing key.
	PublicKey() crypto.PublicKey

	// Certificate returns the signing certificate if available.
	Certificate() *x509.Certificate

	// CertificateChain returns the full certificate chain if available.
	CertificateChain() []*x509.Certificate
}

// DefaultSigner wraps a crypto.PrivateKey and jwt.SigningMethod for local signing.
// This uses a self-signed X.509 certificate by default.
type DefaultSigner struct {
	key    crypto.PrivateKey
	method jwt.SigningMethod
	cert   *x509.Certificate
	chain  []*x509.Certificate
}

// NewDefaultSigner creates a new DefaultSigner using a self-signed X.509 certificate.
func NewDefaultSigner() (*DefaultSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate default signer key: %w", err)
	}
	cert, err := generateSelfSignedCertificate(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate default signer certificate: %w", err)
	}
	return &DefaultSigner{
		key:    key,
		method: jwt.SigningMethodES256,
		cert:   cert,
		chain:  []*x509.Certificate{cert},
	}, nil
}

// Sign signs the JWT content using the wrapped key and signing method.
func (s *DefaultSigner) Sign(signingInput string) ([]byte, error) {
	return s.method.Sign(signingInput, s.key)
}

// Algorithm returns the JWT algorithm identifier from the signing method.
func (s *DefaultSigner) Algorithm() string {
	return s.method.Alg()
}

// PublicKey returns the public key for the signer.
func (s *DefaultSigner) PublicKey() crypto.PublicKey {
	if s == nil || s.key == nil {
		return nil
	}
	if signer, ok := s.key.(crypto.Signer); ok {
		return signer.Public()
	}
	return nil
}

// Certificate returns the signing certificate.
func (s *DefaultSigner) Certificate() *x509.Certificate {
	if s == nil {
		return nil
	}
	return s.cert
}

// CertificateChain returns the signing certificate chain.
func (s *DefaultSigner) CertificateChain() []*x509.Certificate {
	if s == nil {
		return nil
	}
	return s.chain
}

// SigningMethod wraps a Signer to implement jwt.SigningMethod interface.
// This allows using any Signer with the golang-jwt library.
type SigningMethod struct {
	signer Signer
}

// NewSigningMethod creates a jwt.SigningMethod that delegates to the given Signer.
func NewSigningMethod(s Signer) *SigningMethod {
	return &SigningMethod{signer: s}
}

// Alg returns the algorithm name from the wrapped Signer.
func (m *SigningMethod) Alg() string {
	return m.signer.Algorithm()
}

// Sign delegates to the wrapped Signer's Sign method.
// The key parameter is ignored since the Signer manages its own key.
func (m *SigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	return m.signer.Sign(signingString)
}

// Verify is not supported by SigningMethod since it's signing-only.
// For verification, use the standard jwt verification methods.
func (m *SigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	return jwt.ErrSignatureInvalid
}

func generateSelfSignedCertificate(key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SD-JWT Default Signer"},
			CommonName:   "sd-jwt-default-signer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}
