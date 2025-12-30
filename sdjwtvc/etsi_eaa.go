// Package sdjwtvc provides ETSI TS 119 472-1 v1.1.1 support for SD-JWT VC EAA
// (Electronic Attestation of Attributes).
//
// This file implements SD-JWT VC EAA as specified in ETSI TS 119 472-1 v1.1.1,
// which profiles SD-JWT VC for use in the European Union's eIDAS 2.0 framework.
//
// Two categories of EAA are supported:
//   - QEAA (Qualified EAA): Issued by qualified trust service providers
//   - PuB-EAA: Issued by or on behalf of public bodies responsible for authentic sources
package sdjwtvc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// EAA Category URNs as defined in ETSI TS 119 472-1 Section 5.2.2
const (
	// CategoryQEAA is the URN for Qualified Electronic Attestation of Attributes
	// per QEAA-5.2.2.2-02
	CategoryQEAA = "urn:etsi:esi:eaa:eu:qualified"

	// CategoryPuBEAA is the URN for EAA issued by or on behalf of a public body
	// per PuB-EAA-5.2.2.3-02
	CategoryPuBEAA = "urn:etsi:esi:eaa:eu:pub"
)

// Status list types as defined in ETSI TS 119 472-1 Section 5.2.10.1
const (
	// StatusTypeBitstringStatusList is for W3C Bitstring Status List v1.0
	StatusTypeBitstringStatusList = "BitstringStatusListEntry"

	// StatusTypeTokenStatusList is for IETF Token Status List (draft-ietf-oauth-status-list)
	StatusTypeTokenStatusList = "TokenStatusList"
)

// EAACategory represents the category of an EAA
type EAACategory string

const (
	// EAACategoryQEAA represents a Qualified EAA
	EAACategoryQEAA EAACategory = "qeaa"
	// EAACategoryPuBEAA represents a PuB-EAA (public body EAA)
	EAACategoryPuBEAA EAACategory = "pub-eaa"
	// EAACategoryRegular represents a regular EAA (neither QEAA nor PuB-EAA)
	EAACategoryRegular EAACategory = "regular"
)

// EAAPayload represents the payload of an ETSI SD-JWT VC EAA as defined in
// ETSI TS 119 472-1 Section 5.2.
type EAAPayload struct {
	// === Required claims per ETSI TS 119 472-1 ===

	// VCT is the Verifiable Credential Type URI (REQUIRED per EAA-5.2.1.2-01)
	VCT string `json:"vct"`

	// VCTIntegrity is the cryptographic hash of the VCT document (REQUIRED per EAA-5.2.1.2-03)
	VCTIntegrity string `json:"vct#integrity"`

	// Issuer is the issuer URI (REQUIRED per EAA-5.2.4.1-02)
	Issuer string `json:"iss"`

	// JTI is the EAA identifier (REQUIRED per EAA-5.2.3-02)
	JTI string `json:"jti"`

	// NotBefore is the technical validity start time (REQUIRED per EAA-5.2.7.1-01)
	NotBefore int64 `json:"nbf"`

	// ExpirationTime is the technical validity end time (REQUIRED per EAA-5.2.7.1-03)
	ExpirationTime int64 `json:"exp"`

	// === Optional/conditional claims ===

	// Category is the EAA category URN (REQUIRED for QEAA/PuB-EAA per 5.2.2)
	// For regular EAA, this should be empty.
	Category string `json:"category,omitempty"`

	// Subject is the EAA subject identifier (per EAA-5.2.5.1-02, either sub or also_known_as required)
	Subject string `json:"sub,omitempty"`

	// AlsoKnownAs is the EAA subject pseudonym (per EAA-5.2.5.1-02)
	AlsoKnownAs string `json:"also_known_as,omitempty"`

	// IssuedAt is when the EAA was issued (OPTIONAL per EAA-5.2.6-02)
	IssuedAt int64 `json:"iat,omitempty"`

	// IssuingAuthority is the name of the EAA issuer (REQUIRED for QEAA/PuB-EAA per 5.2.4)
	IssuingAuthority string `json:"issuing_authority,omitempty"`

	// IssuingCountry is the EU Member country code (REQUIRED for QEAA/PuB-EAA per 5.2.4)
	IssuingCountry string `json:"issuing_country,omitempty"`

	// IssuerRegistrationID is the issuer's registration identifier (per EAA-5.2.4.1-09)
	IssuerRegistrationID string `json:"iss_reg_id,omitempty"`

	// AdministrativeNotBefore is the administrative validity start time (OPTIONAL per EAA-5.2.7.2-01)
	// Must be present if AdministrativeExpiration is present.
	AdministrativeNotBefore *int64 `json:"adm_nbf,omitempty"`

	// AdministrativeExpiration is the administrative validity end time (OPTIONAL per EAA-5.2.7.2-03)
	// Must be present if AdministrativeNotBefore is present.
	AdministrativeExpiration *int64 `json:"adm_exp,omitempty"`

	// OneTime indicates the EAA should be used only once (OPTIONAL per EAA-5.2.8.2-02)
	// When present, the value is JSON null. Use pointer to distinguish presence.
	OneTime *struct{} `json:"oneTime,omitempty"`

	// ShortLived indicates the EAA is short-lived (OPTIONAL per EAA-5.2.12-01)
	// When present, the value is JSON null. Use pointer to distinguish presence.
	ShortLived *struct{} `json:"shortLived,omitempty"`

	// CNF is the confirmation claim for key binding (OPTIONAL per EAA-5.5-01)
	CNF *EAACNFClaim `json:"cnf,omitempty"`

	// Status contains status/revocation information (OPTIONAL per EAA-5.2.10.1-02)
	// REQUIRED for QEAA and PuB-EAA.
	Status *EAAStatus `json:"status,omitempty"`

	// SubAttrs contains attributes for entities other than the EAA subject (per EAA-5.3-03)
	SubAttrs []SubjectAttributes `json:"subAttrs,omitempty"`

	// Extra contains additional application-specific claims
	Extra map[string]any `json:"-"`
}

// EAACNFClaim represents the confirmation claim with support for both JWK and X.509
// certificates as specified in ETSI TS 119 472-1 Section 5.5.
type EAACNFClaim struct {
	// JWK contains the holder's public key in JWK format (per EAA-5.5-06, recommended)
	JWK json.RawMessage `json:"jwk,omitempty"`

	// X5C contains the X.509 certificate chain (per EAA-5.5-03)
	// If present, X5U and X5TS256 should not be present.
	X5C []string `json:"x5c,omitempty"`

	// X5TS256 is the SHA-256 thumbprint of the certificate (per EAA-5.5-03)
	// Required if X5U is present.
	X5TS256 string `json:"x5t#S256,omitempty"`

	// X5U is the URL to the X.509 certificate (per EAA-5.5-03)
	// If present, X5TS256 must also be present.
	X5U string `json:"x5u,omitempty"`
}

// EAAStatus represents the status claim as specified in ETSI TS 119 472-1 Section 5.2.10.
type EAAStatus struct {
	// Type is the status list type (REQUIRED per EAA-5.2.10.1-04)
	// Values: "BitstringStatusListEntry" or "TokenStatusList"
	Type string `json:"type"`

	// Purpose indicates the purpose of the status list (REQUIRED per EAA-5.2.10.1-06)
	Purpose string `json:"purpose"`

	// Index is the index in the status list (REQUIRED per EAA-5.2.10.1-08)
	Index int `json:"index"`

	// URI is the URL pointing to the status list (REQUIRED per EAA-5.2.10.1-10)
	URI string `json:"uri"`

	// Additional members may be present per EAA-5.2.10.1-12
	Extra map[string]any `json:"-"`
}

// SubjectAttributes represents attributes associated with an entity different than
// the EAA subject, as specified in ETSI TS 119 472-1 Section 5.3.
type SubjectAttributes struct {
	// SubjectID is the identifier of the attribute subject (per EAA-5.3-05)
	// Either SubjectID or SubjectPseudonym must be present.
	SubjectID string `json:"sub_id,omitempty"`

	// SubjectPseudonym is the pseudonym of the attribute subject (per EAA-5.3-06)
	// Either SubjectID or SubjectPseudonym must be present.
	SubjectPseudonym string `json:"sub_aka,omitempty"`

	// Attributes is the array of attributes associated with this subject (REQUIRED per EAA-5.3-07)
	Attributes []any `json:"attrs"`
}

// X509HeaderParams contains X.509 certificate parameters for JWT headers
// as required by ETSI TS 119 472-1 Section 5.6.
type X509HeaderParams struct {
	// X5U is the URL to the signing certificate (REQUIRED for QEAA/PuB-EAA per 5.6.2-02)
	X5U string `json:"x5u,omitempty"`

	// X5TS256 is the SHA-256 thumbprint of the signing certificate (REQUIRED for QEAA/PuB-EAA per 5.6.2-02)
	X5TS256 string `json:"x5t#S256,omitempty"`

	// X5C is the X.509 certificate chain (SHOULD be present per QEAA-5.6.2-03)
	X5C []string `json:"x5c,omitempty"`
}

// EAAIssuerConfig contains configuration for an ETSI EAA issuer.
type EAAIssuerConfig struct {
	// Category specifies the EAA category (QEAA, PuB-EAA, or regular)
	Category EAACategory

	// IssuerID is the issuer URI (REQUIRED per EAA-5.2.4.1-02)
	IssuerID string

	// IssuingAuthority is the name of the issuing authority
	// REQUIRED for QEAA and PuB-EAA
	IssuingAuthority string

	// IssuingCountry is the EU Member country code (ISO 3166-1 alpha-2)
	// REQUIRED for QEAA and PuB-EAA
	IssuingCountry string

	// IssuerRegistrationID is the issuer's registration identifier
	// REQUIRED for QEAA/PuB-EAA when the issuer is a legal person
	IssuerRegistrationID string

	// Signer is the signer used to sign JWTs (REQUIRED).
	Signer signer.Signer

	// SigningCertificate is the X.509 certificate for signing
	// REQUIRED for QEAA and PuB-EAA to include x5c in headers
	SigningCertificate *x509.Certificate

	// SigningCertificateChain is the full certificate chain
	SigningCertificateChain []*x509.Certificate

	// SigningCertificateURL is the URL where the certificate can be retrieved
	// REQUIRED for QEAA and PuB-EAA per 5.6.2-02
	SigningCertificateURL string

	// HashAlgorithm is the hash algorithm for disclosures (default: sha-256)
	HashAlgorithm string
}

// EAAIssuer creates SD-JWT VC EAAs conformant to ETSI TS 119 472-1.
type EAAIssuer struct {
	config EAAIssuerConfig
	issuer *issuer.Issuer
}

// NewEAAIssuer creates a new ETSI EAA issuer with the given configuration.
func NewEAAIssuer(config EAAIssuerConfig) (*EAAIssuer, error) {
	if config.Signer == nil {
		return nil, fmt.Errorf("signer is required for EAA issuer")
	}
	if config.SigningCertificate == nil {
		config.SigningCertificate = config.Signer.Certificate()
	}
	if len(config.SigningCertificateChain) == 0 {
		if chain := config.Signer.CertificateChain(); len(chain) > 0 {
			config.SigningCertificateChain = chain
		}
	}
	// Validate configuration based on category
	if err := validateEAAIssuerConfig(config); err != nil {
		return nil, err
	}

	iss := issuer.NewIssuer(config.Signer)

	return &EAAIssuer{
		config: config,
		issuer: iss,
	}, nil
}

// validateEAAIssuerConfig validates the issuer configuration based on EAA category.
func validateEAAIssuerConfig(config EAAIssuerConfig) error {
	if config.IssuerID == "" {
		return fmt.Errorf("IssuerID is required per EAA-5.2.4.1-02")
	}

	if config.Category == EAACategoryQEAA || config.Category == EAACategoryPuBEAA {
		if config.IssuingAuthority == "" {
			return fmt.Errorf("IssuingAuthority is required for %s", config.Category)
		}
		if config.IssuingCountry == "" {
			return fmt.Errorf("IssuingCountry is required for %s", config.Category)
		}
		if config.SigningCertificateURL == "" {
			return fmt.Errorf("SigningCertificateURL is required for %s per 5.6.2-02", config.Category)
		}
		if config.SigningCertificate == nil {
			return fmt.Errorf("SigningCertificate is required for %s to compute x5t#S256", config.Category)
		}
	}

	return nil
}

// EAAIssueOptions contains options for issuing an EAA.
type EAAIssueOptions struct {
	// VCT is the Verifiable Credential Type URI (REQUIRED)
	VCT string

	// VCTIntegrity is the cryptographic hash of the VCT document (REQUIRED per EAA-5.2.1.2-03)
	VCTIntegrity string

	// JTI is the EAA identifier (REQUIRED per EAA-5.2.3-02)
	// If empty, a UUID should be generated.
	JTI string

	// Subject is the subject of the EAA (per EAA-5.2.5.1-02, either Subject or Pseudonym required)
	Subject string

	// Pseudonym is the subject pseudonym (per EAA-5.2.5.2-01)
	Pseudonym string

	// IssuedAt is when the EAA was issued (defaults to now)
	IssuedAt *time.Time

	// NotBefore is when the EAA becomes technically valid (REQUIRED per EAA-5.2.7.1-01)
	NotBefore time.Time

	// ExpirationTime is when the EAA expires technically (REQUIRED per EAA-5.2.7.1-03)
	ExpirationTime time.Time

	// AdministrativeNotBefore is the administrative validity start (OPTIONAL)
	AdministrativeNotBefore *time.Time

	// AdministrativeExpiration is the administrative validity end (OPTIONAL)
	// If AdministrativeNotBefore is set, this must also be set.
	AdministrativeExpiration *time.Time

	// HolderPublicKey is the holder's public key for key binding in JWK format
	HolderPublicKey json.RawMessage

	// HolderCertificate is the holder's X.509 certificate for key binding
	HolderCertificate *x509.Certificate

	// HolderCertificateURL is the URL to the holder's certificate
	HolderCertificateURL string

	// Status is the status reference for revocation (REQUIRED for QEAA/PuB-EAA)
	Status *EAAStatus

	// OneTime indicates the EAA should be used only once
	OneTime bool

	// ShortLived indicates the EAA is short-lived
	ShortLived bool

	// SubjectAttributes contains attributes for entities other than the EAA subject
	SubjectAttributes []SubjectAttributes

	// DecoyDigests is the number of decoy digests to add
	DecoyDigests int
}

// Issue creates an ETSI SD-JWT VC EAA from a disclosure frame and claims.
func (e *EAAIssuer) Issue(claims map[string]any, frame *sdjwt.DisclosureFrame, opts EAAIssueOptions) (*sdjwt.SDJWT, error) {
	// Validate required fields
	if err := e.validateIssueOptions(opts); err != nil {
		return nil, err
	}

	// Build the full payload
	payload := make(map[string]any)

	// Copy user claims (attested attributes)
	for k, val := range claims {
		payload[k] = val
	}

	// Add required claims per ETSI TS 119 472-1 Section 5.2
	payload["iss"] = e.config.IssuerID
	payload["vct"] = opts.VCT
	payload["vct#integrity"] = opts.VCTIntegrity
	payload["jti"] = opts.JTI
	payload["nbf"] = opts.NotBefore.Unix()
	payload["exp"] = opts.ExpirationTime.Unix()

	// Add category for QEAA/PuB-EAA
	switch e.config.Category {
	case EAACategoryQEAA:
		payload["category"] = CategoryQEAA
	case EAACategoryPuBEAA:
		payload["category"] = CategoryPuBEAA
		// Regular EAA: no category claim per EAA-5.2.2.1-01
	}

	// Add issuer identification claims
	if e.config.IssuingAuthority != "" {
		payload["issuing_authority"] = e.config.IssuingAuthority
	}
	if e.config.IssuingCountry != "" {
		payload["issuing_country"] = e.config.IssuingCountry
	}
	if e.config.IssuerRegistrationID != "" {
		payload["iss_reg_id"] = e.config.IssuerRegistrationID
	}

	// Add subject identification
	if opts.Subject != "" {
		payload["sub"] = opts.Subject
	}
	if opts.Pseudonym != "" {
		payload["also_known_as"] = opts.Pseudonym
	}

	// Add issuance time
	if opts.IssuedAt != nil {
		payload["iat"] = opts.IssuedAt.Unix()
	} else {
		payload["iat"] = time.Now().Unix()
	}

	// Add administrative validity period
	if opts.AdministrativeNotBefore != nil && opts.AdministrativeExpiration != nil {
		payload["adm_nbf"] = opts.AdministrativeNotBefore.Unix()
		payload["adm_exp"] = opts.AdministrativeExpiration.Unix()
	}

	// Add usage constraints
	if opts.OneTime {
		payload["oneTime"] = nil // JSON null
	}
	if opts.ShortLived {
		payload["shortLived"] = nil // JSON null
	}

	// Add CNF claim
	cnf := e.buildCNFClaim(opts)
	if cnf != nil {
		payload["cnf"] = cnf
	}

	// Add status claim
	if opts.Status != nil {
		payload["status"] = map[string]any{
			"type":    opts.Status.Type,
			"purpose": opts.Status.Purpose,
			"index":   opts.Status.Index,
			"uri":     opts.Status.URI,
		}
	}

	// Add subject attributes for different entities
	if len(opts.SubjectAttributes) > 0 {
		subAttrs := make([]map[string]any, len(opts.SubjectAttributes))
		for i, sa := range opts.SubjectAttributes {
			attr := make(map[string]any)
			if sa.SubjectID != "" {
				attr["sub_id"] = sa.SubjectID
			}
			if sa.SubjectPseudonym != "" {
				attr["sub_aka"] = sa.SubjectPseudonym
			}
			attr["attrs"] = sa.Attributes
			subAttrs[i] = attr
		}
		payload["subAttrs"] = subAttrs
	}

	// Build issue options with X.509 headers for QEAA/PuB-EAA
	issueOpts := &issuer.IssueOptions{
		HashAlgorithm: e.config.HashAlgorithm,
		Type:          TypeHeader,
		ExtraHeaders:  e.buildX509Headers(),
	}

	// Add decoy digests
	if frame == nil {
		frame = &sdjwt.DisclosureFrame{}
	}
	if opts.DecoyDigests > 0 {
		frame.SDDecoy = opts.DecoyDigests
	}

	return e.issuer.IssueWithFrame(payload, frame, issueOpts)
}

// validateIssueOptions validates the issue options.
func (e *EAAIssuer) validateIssueOptions(opts EAAIssueOptions) error {
	if opts.VCT == "" {
		return fmt.Errorf("VCT is required per EAA-5.2.1.2-01")
	}
	if opts.VCTIntegrity == "" {
		return fmt.Errorf("VCTIntegrity is required per EAA-5.2.1.2-03")
	}
	if opts.JTI == "" {
		return fmt.Errorf("JTI (EAA identifier) is required per EAA-5.2.3-02")
	}
	if opts.NotBefore.IsZero() {
		return fmt.Errorf("NotBefore is required per EAA-5.2.7.1-01")
	}
	if opts.ExpirationTime.IsZero() {
		return fmt.Errorf("ExpirationTime is required per EAA-5.2.7.1-03")
	}

	// Per EAA-5.2.5.1-02: either sub or also_known_as required
	if opts.Subject == "" && opts.Pseudonym == "" {
		return fmt.Errorf("either Subject or Pseudonym is required per EAA-5.2.5.1-02")
	}

	// Per EAA-5.2.7.2-05: both adm_nbf and adm_exp or neither
	if (opts.AdministrativeNotBefore != nil) != (opts.AdministrativeExpiration != nil) {
		return fmt.Errorf("both AdministrativeNotBefore and AdministrativeExpiration must be set or neither per EAA-5.2.7.2-05")
	}

	// Status required for QEAA/PuB-EAA
	if (e.config.Category == EAACategoryQEAA || e.config.Category == EAACategoryPuBEAA) && opts.Status == nil {
		return fmt.Errorf("Status is required for %s per 5.2.10.2/5.2.10.3", e.config.Category)
	}

	// Validate SubjectAttributes
	for i, sa := range opts.SubjectAttributes {
		if sa.SubjectID == "" && sa.SubjectPseudonym == "" {
			return fmt.Errorf("SubjectAttributes[%d] must have either SubjectID or SubjectPseudonym per EAA-5.3-04", i)
		}
		if sa.Attributes == nil {
			return fmt.Errorf("SubjectAttributes[%d] must have Attributes per EAA-5.3-07", i)
		}
	}

	return nil
}

// buildCNFClaim builds the CNF claim from the options.
func (e *EAAIssuer) buildCNFClaim(opts EAAIssueOptions) map[string]any {
	if opts.HolderPublicKey == nil && opts.HolderCertificate == nil {
		return nil
	}

	cnf := make(map[string]any)

	if opts.HolderPublicKey != nil {
		var jwk map[string]any
		if err := json.Unmarshal(opts.HolderPublicKey, &jwk); err == nil {
			cnf["jwk"] = jwk
		}
	}

	if opts.HolderCertificate != nil {
		// Per EAA-5.5-03 and EAA-5.5-05: if x5c present, no x5u or x5t#S256
		if opts.HolderCertificateURL == "" {
			// Use x5c only
			cnf["x5c"] = []string{base64.StdEncoding.EncodeToString(opts.HolderCertificate.Raw)}
		} else {
			// Per EAA-5.5-04: if x5u present, x5t#S256 must also be present
			cnf["x5u"] = opts.HolderCertificateURL
			cnf["x5t#S256"] = computeCertThumbprint(opts.HolderCertificate)
		}
	}

	return cnf
}

// buildX509Headers builds X.509 header parameters for QEAA/PuB-EAA signatures.
func (e *EAAIssuer) buildX509Headers() map[string]any {
	if e.config.Category != EAACategoryQEAA && e.config.Category != EAACategoryPuBEAA {
		return nil
	}

	headers := make(map[string]any)

	// Per QEAA-5.6.2-02 / PuB-EAA-5.6.3-02: x5u and x5t#S256 required
	if e.config.SigningCertificateURL != "" {
		headers["x5u"] = e.config.SigningCertificateURL
	}
	if e.config.SigningCertificate != nil {
		headers["x5t#S256"] = computeCertThumbprint(e.config.SigningCertificate)
	}

	// Per QEAA-5.6.2-03 / PuB-EAA-5.6.3-03: x5c SHOULD be present
	if len(e.config.SigningCertificateChain) > 0 {
		x5c := make([]string, len(e.config.SigningCertificateChain))
		for i, cert := range e.config.SigningCertificateChain {
			x5c[i] = base64.StdEncoding.EncodeToString(cert.Raw)
		}
		headers["x5c"] = x5c
	} else if e.config.SigningCertificate != nil {
		headers["x5c"] = []string{base64.StdEncoding.EncodeToString(e.config.SigningCertificate.Raw)}
	}

	return headers
}

// computeCertThumbprint computes the SHA-256 thumbprint of an X.509 certificate.
func computeCertThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// EAAValidationOptions contains options for EAA validation.
type EAAValidationOptions struct {
	// ExpectedCategory is the expected EAA category (if set, validates category)
	ExpectedCategory *EAACategory

	// SkipExpirationCheck skips the technical expiration time check
	SkipExpirationCheck bool

	// SkipNotBeforeCheck skips the technical not-before time check
	SkipNotBeforeCheck bool

	// SkipAdministrativeValidityCheck skips administrative validity checking
	SkipAdministrativeValidityCheck bool

	// AllowedClockSkew is the allowed clock skew for time validation
	AllowedClockSkew time.Duration

	// Now overrides the current time for validation
	Now *time.Time
}

// ValidateEAA validates an EAA payload against ETSI TS 119 472-1 requirements.
func ValidateEAA(payload map[string]any, opts *EAAValidationOptions) error {
	if opts == nil {
		opts = &EAAValidationOptions{}
	}

	now := time.Now()
	if opts.Now != nil {
		now = *opts.Now
	}
	nowUnix := now.Unix()

	// Validate required claims per Section 5.2

	// vct is REQUIRED per EAA-5.2.1.2-01
	if _, ok := payload["vct"]; !ok {
		return fmt.Errorf("missing required claim: vct (per EAA-5.2.1.2-01)")
	}
	if vct, ok := payload["vct"].(string); !ok || vct == "" {
		return fmt.Errorf("vct must be a non-empty string")
	}

	// vct#integrity is REQUIRED per EAA-5.2.1.2-03
	if _, ok := payload["vct#integrity"]; !ok {
		return fmt.Errorf("missing required claim: vct#integrity (per EAA-5.2.1.2-03)")
	}

	// iss is REQUIRED per EAA-5.2.4.1-02
	if _, ok := payload["iss"]; !ok {
		return fmt.Errorf("missing required claim: iss (per EAA-5.2.4.1-02)")
	}

	// jti is REQUIRED per EAA-5.2.3-02
	if _, ok := payload["jti"]; !ok {
		return fmt.Errorf("missing required claim: jti (per EAA-5.2.3-02)")
	}

	// nbf is REQUIRED per EAA-5.2.7.1-01
	if _, ok := payload["nbf"]; !ok {
		return fmt.Errorf("missing required claim: nbf (per EAA-5.2.7.1-01)")
	}

	// exp is REQUIRED per EAA-5.2.7.1-03
	if _, ok := payload["exp"]; !ok {
		return fmt.Errorf("missing required claim: exp (per EAA-5.2.7.1-03)")
	}

	// Validate subject identification per EAA-5.2.5.1-02
	_, hasSub := payload["sub"]
	_, hasAka := payload["also_known_as"]
	if !hasSub && !hasAka {
		return fmt.Errorf("either sub or also_known_as is required (per EAA-5.2.5.1-02)")
	}

	// Validate category
	if opts.ExpectedCategory != nil {
		category, hasCategory := payload["category"]
		switch *opts.ExpectedCategory {
		case EAACategoryQEAA:
			if !hasCategory || category != CategoryQEAA {
				return fmt.Errorf("expected QEAA category %q", CategoryQEAA)
			}
		case EAACategoryPuBEAA:
			if !hasCategory || category != CategoryPuBEAA {
				return fmt.Errorf("expected PuB-EAA category %q", CategoryPuBEAA)
			}
		case EAACategoryRegular:
			if hasCategory {
				return fmt.Errorf("regular EAA should not have category claim")
			}
		}
	}

	// Validate QEAA/PuB-EAA specific requirements
	if category, ok := payload["category"].(string); ok {
		if category == CategoryQEAA || category == CategoryPuBEAA {
			// issuing_authority is REQUIRED
			if _, ok := payload["issuing_authority"]; !ok {
				return fmt.Errorf("missing required claim for %s: issuing_authority", category)
			}
			// issuing_country is REQUIRED
			if _, ok := payload["issuing_country"]; !ok {
				return fmt.Errorf("missing required claim for %s: issuing_country", category)
			}
			// status is REQUIRED
			if _, ok := payload["status"]; !ok {
				return fmt.Errorf("missing required claim for %s: status", category)
			}
		}
	}

	// Validate time claims
	if !opts.SkipNotBeforeCheck {
		if nbf, ok := payload["nbf"]; ok {
			nbfTime, err := toInt64(nbf)
			if err != nil {
				return fmt.Errorf("nbf must be a number: %w", err)
			}
			if nbfTime > nowUnix+int64(opts.AllowedClockSkew.Seconds()) {
				return fmt.Errorf("EAA not yet valid (nbf: %d, now: %d)", nbfTime, nowUnix)
			}
		}
	}

	if !opts.SkipExpirationCheck {
		if exp, ok := payload["exp"]; ok {
			expTime, err := toInt64(exp)
			if err != nil {
				return fmt.Errorf("exp must be a number: %w", err)
			}
			if expTime < nowUnix-int64(opts.AllowedClockSkew.Seconds()) {
				return fmt.Errorf("EAA has expired (exp: %d, now: %d)", expTime, nowUnix)
			}
		}
	}

	// Validate administrative validity per EAA-5.2.7.2-05
	admNbf, hasAdmNbf := payload["adm_nbf"]
	admExp, hasAdmExp := payload["adm_exp"]
	if hasAdmNbf != hasAdmExp {
		return fmt.Errorf("adm_nbf and adm_exp must both be present or both absent (per EAA-5.2.7.2-05)")
	}

	if !opts.SkipAdministrativeValidityCheck && hasAdmNbf && hasAdmExp {
		admNbfTime, err := toInt64(admNbf)
		if err != nil {
			return fmt.Errorf("adm_nbf must be a number: %w", err)
		}
		admExpTime, err := toInt64(admExp)
		if err != nil {
			return fmt.Errorf("adm_exp must be a number: %w", err)
		}

		if admNbfTime > nowUnix+int64(opts.AllowedClockSkew.Seconds()) {
			return fmt.Errorf("EAA not yet administratively valid (adm_nbf: %d, now: %d)", admNbfTime, nowUnix)
		}
		if admExpTime < nowUnix-int64(opts.AllowedClockSkew.Seconds()) {
			return fmt.Errorf("EAA has administratively expired (adm_exp: %d, now: %d)", admExpTime, nowUnix)
		}
	}

	// Validate status structure if present
	if statusClaim, ok := payload["status"]; ok {
		if err := validateEAAStatus(statusClaim); err != nil {
			return err
		}
	}

	// Validate subAttrs if present
	if subAttrsClaim, ok := payload["subAttrs"]; ok {
		if err := validateSubAttrs(subAttrsClaim); err != nil {
			return err
		}
	}

	// Validate CNF claim if present
	if cnfClaim, ok := payload["cnf"]; ok {
		if err := validateEAACNF(cnfClaim); err != nil {
			return err
		}
	}

	return nil
}

// validateEAAStatus validates the status claim structure per Section 5.2.10.
func validateEAAStatus(statusClaim any) error {
	status, ok := statusClaim.(map[string]any)
	if !ok {
		return fmt.Errorf("status must be a JSON Object (per EAA-5.2.10.1-03)")
	}

	// type is REQUIRED per EAA-5.2.10.1-04
	if _, ok := status["type"]; !ok {
		return fmt.Errorf("status.type is required (per EAA-5.2.10.1-04)")
	}
	if _, ok := status["type"].(string); !ok {
		return fmt.Errorf("status.type must be a JSON String (per EAA-5.2.10.1-05)")
	}

	// purpose is REQUIRED per EAA-5.2.10.1-06
	if _, ok := status["purpose"]; !ok {
		return fmt.Errorf("status.purpose is required (per EAA-5.2.10.1-06)")
	}
	if _, ok := status["purpose"].(string); !ok {
		return fmt.Errorf("status.purpose must be a JSON String (per EAA-5.2.10.1-07)")
	}

	// index is REQUIRED per EAA-5.2.10.1-08
	if _, ok := status["index"]; !ok {
		return fmt.Errorf("status.index is required (per EAA-5.2.10.1-08)")
	}
	// index should be an integer
	if _, err := toInt64(status["index"]); err != nil {
		return fmt.Errorf("status.index must be a JSON Integer (per EAA-5.2.10.1-09): %w", err)
	}

	// uri is REQUIRED per EAA-5.2.10.1-10
	if _, ok := status["uri"]; !ok {
		return fmt.Errorf("status.uri is required (per EAA-5.2.10.1-10)")
	}
	if _, ok := status["uri"].(string); !ok {
		return fmt.Errorf("status.uri must be a JSON String (per EAA-5.2.10.1-11)")
	}

	return nil
}

// validateSubAttrs validates the subAttrs claim per Section 5.3.
func validateSubAttrs(subAttrsClaim any) error {
	subAttrs, ok := subAttrsClaim.([]any)
	if !ok {
		return fmt.Errorf("subAttrs must be a JSON Array")
	}

	for i, item := range subAttrs {
		sa, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("subAttrs[%d] must be a JSON Object", i)
		}

		// Per EAA-5.3-04: either sub_id or sub_aka required
		_, hasSubID := sa["sub_id"]
		_, hasSubAka := sa["sub_aka"]
		if !hasSubID && !hasSubAka {
			return fmt.Errorf("subAttrs[%d] must have either sub_id or sub_aka (per EAA-5.3-04)", i)
		}

		// Per EAA-5.3-07: attrs is required
		if _, ok := sa["attrs"]; !ok {
			return fmt.Errorf("subAttrs[%d].attrs is required (per EAA-5.3-07)", i)
		}
		// Per EAA-5.3-08: attrs must be a JSON Array
		if _, ok := sa["attrs"].([]any); !ok {
			return fmt.Errorf("subAttrs[%d].attrs must be a JSON Array (per EAA-5.3-08)", i)
		}
	}

	return nil
}

// validateEAACNF validates the CNF claim per Section 5.5.
func validateEAACNF(cnfClaim any) error {
	cnf, ok := cnfClaim.(map[string]any)
	if !ok {
		return fmt.Errorf("cnf must be a JSON Object")
	}

	// Per EAA-5.5-02: cnf may only contain JWK or X.509 cert representation
	_, hasJWK := cnf["jwk"]
	_, hasX5C := cnf["x5c"]
	_, hasX5U := cnf["x5u"]
	x5ts256, hasX5TS256 := cnf["x5t#S256"]

	// Per EAA-5.5-05: if x5c present, no x5u or x5t#S256
	if hasX5C && (hasX5U || hasX5TS256) {
		return fmt.Errorf("if cnf.x5c is present, x5u and x5t#S256 should not be present (per EAA-5.5-05)")
	}

	// Per EAA-5.5-04: if x5u present, x5t#S256 must also be present
	if hasX5U && !hasX5TS256 {
		return fmt.Errorf("if cnf.x5u is present, x5t#S256 must also be present (per EAA-5.5-04)")
	}

	// Validate x5t#S256 is a string if present
	if hasX5TS256 {
		if _, ok := x5ts256.(string); !ok {
			return fmt.Errorf("cnf.x5t#S256 must be a string")
		}
	}

	// At least one key representation should be present
	if !hasJWK && !hasX5C && !hasX5U {
		return fmt.Errorf("cnf must contain either jwk or X.509 certificate representation")
	}

	return nil
}

// ETSI EAA specific claims that MUST NOT be selectively disclosed
// per ETSI TS 119 472-1 Section 5.4 and SD-JWT VC Section 3.2.2.2
var EAAClaimsNotSelectivelyDisclosable = []string{
	"iss",
	"vct",
	"vct#integrity",
	"jti",
	"nbf",
	"exp",
	"category",
	"issuing_authority",
	"issuing_country",
	"iss_reg_id",
	"adm_nbf",
	"adm_exp",
	"cnf",
	"status",
	"oneTime",
	"shortLived",
}

// EAAClaimsMayBeSelectivelyDisclosed are claims that MAY be selectively disclosed
var EAAClaimsMayBeSelectivelyDisclosed = []string{
	"sub",
	"also_known_as",
	"iat",
	"subAttrs",
}

// IsEAAClaimSelectivelyDisclosable checks if a claim can be selectively disclosed
// per ETSI TS 119 472-1 Section 5.4.
func IsEAAClaimSelectivelyDisclosable(name string) bool {
	for _, claim := range EAAClaimsNotSelectivelyDisclosable {
		if name == claim {
			return false
		}
	}
	return true
}
