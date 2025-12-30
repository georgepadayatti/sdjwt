// Package issuer provides functionality for creating SD-JWTs using the frame-based API.
package issuer

import "github.com/georgepadayatti/sdjwt/signer"

// Issuer creates SD-JWTs using disclosure frames.
type Issuer struct {
	// Signer is used to sign JWTs. It can be a DefaultSigner (for local keys)
	// or a custom implementation for HSMs, cloud KMS, etc.
	Signer signer.Signer
}

// NewIssuer creates a new Issuer with the given signer.
func NewIssuer(s signer.Signer) *Issuer {
	return &Issuer{
		Signer: s,
	}
}
