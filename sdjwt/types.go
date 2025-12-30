// Package sdjwt provides core types and utilities for SD-JWT (Selective Disclosure JWT)
// as specified in RFC 9901.
package sdjwt

import "encoding/json"

// SDJWT represents a Selective Disclosure JWT consisting of an issuer-signed JWT
// and zero or more disclosures.
type SDJWT struct {
	// IssuerSignedJWT is the signed JWT component (header.payload.signature)
	IssuerSignedJWT string

	// Disclosures contains all the disclosure strings
	Disclosures []Disclosure

	// HashAlgorithm is the hash algorithm used (_sd_alg claim value)
	// Defaults to "sha-256" if not specified
	HashAlgorithm string
}

// SDJWTWithKB represents an SD-JWT combined with a Key Binding JWT.
// This is used when the holder needs to prove possession of a key.
type SDJWTWithKB struct {
	// SDJWT is the underlying SD-JWT
	SDJWT SDJWT

	// KeyBindingJWT is the Key Binding JWT proving holder possession
	KeyBindingJWT string
}

// Disclosure represents a single selective disclosure.
// For object properties: [salt, claim_name, claim_value]
// For array elements: [salt, value]
type Disclosure struct {
	// Salt is the random salt value (base64url encoded random bytes)
	Salt string

	// ClaimName is the name of the claim (empty for array elements)
	ClaimName string

	// ClaimValue is the value of the claim (can be any JSON type)
	ClaimValue any

	// Encoded is the base64url-encoded disclosure string
	Encoded string

	// Digest is the base64url-encoded hash of the encoded disclosure
	Digest string

	// ArrayElement indicates whether this disclosure represents an array element.
	ArrayElement bool
}

// IsArrayElement returns true if this disclosure is for an array element
// (i.e., has no claim name)
func (d *Disclosure) IsArrayElement() bool {
	return d.ArrayElement
}

// CNFClaim represents the confirmation claim (cnf) containing the holder's key.
// Per RFC 7800 and ETSI TS 119 472-1, this supports both JWK and X.509 certificates.
type CNFClaim struct {
	// JWK contains the holder's public key in JWK format
	JWK json.RawMessage `json:"jwk,omitempty"`

	// X5C contains the X.509 certificate chain (base64-encoded DER)
	// Per ETSI TS 119 472-1 Section 5.5, if x5c is present, x5u and X5TS256 should not be present.
	X5C []string `json:"x5c,omitempty"`

	// X5TS256 is the SHA-256 thumbprint of the certificate (base64url-encoded)
	// Per ETSI TS 119 472-1 Section 5.5, required if X5U is present.
	X5TS256 string `json:"x5t#S256,omitempty"`

	// X5U is the URL to the X.509 certificate
	// Per ETSI TS 119 472-1 Section 5.5, if present, X5TS256 must also be present.
	X5U string `json:"x5u,omitempty"`
}

// ProcessedPayload represents the result of processing an SD-JWT,
// with all disclosed claims merged into the payload.
type ProcessedPayload struct {
	// Claims contains all the processed claims (disclosed + non-SD claims)
	Claims map[string]any

	// CNF is the confirmation claim if present (for key binding)
	CNF *CNFClaim
}

// SDJWTPayload represents the payload of an SD-JWT before processing.
// This is used internally during verification.
type SDJWTPayload struct {
	// Standard JWT claims
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`

	// SD-JWT specific claims
	SDAlg string   `json:"_sd_alg,omitempty"`
	SD    []string `json:"_sd,omitempty"`

	// Confirmation claim for key binding
	CNF *CNFClaim `json:"cnf,omitempty"`

	// Additional claims (non-SD)
	Extra map[string]any `json:"-"`
}

// KeyBindingJWTPayload represents the payload of a Key Binding JWT.
type KeyBindingJWTPayload struct {
	// IssuedAt is the time the KB-JWT was created
	IssuedAt int64 `json:"iat"`

	// Audience identifies the verifier
	Audience string `json:"aud"`

	// Nonce is a random value for replay protection
	Nonce string `json:"nonce"`

	// SDHash is the hash of the SD-JWT (without KB-JWT)
	SDHash string `json:"sd_hash"`
}

// ArrayElementDigest represents a digest placeholder in an array.
// Format: {"...": "<digest>"}
type ArrayElementDigest struct {
	Digest string `json:"..."`
}

// DefaultHashAlgorithm is the default hash algorithm if not specified.
const DefaultHashAlgorithm = "sha-256"

// KBJWTType is the required type for Key Binding JWTs.
const KBJWTType = "kb+jwt"

// Separator is the tilde character used to separate SD-JWT components.
const Separator = "~"
