// Package sdjwtvc implements SD-JWT based Verifiable Credentials (SD-JWT VC)
// as specified in draft-ietf-oauth-sd-jwt-vc-13.
//
// This implementation provides:
//   - VCIssuer for creating SD-JWT VCs with selective disclosure
//   - Type metadata structures per Section 6 of the specification
//   - Display metadata structures per Section 8 of the specification
//   - Claim metadata structures per Section 9 of the specification
//   - Status list integration for credential revocation
//   - Full validation per Section 3.4 of the specification
package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/statuslist"
)

// MediaType is the media type for SD-JWT VC as defined in Section 3.1.
// The media type "application/dc+sd-jwt" MUST be used.
const MediaType = "application/dc+sd-jwt"

// TypeHeader is the typ header value for SD-JWT VC as defined in Section 3.2.1.
// The typ header MUST be set to "dc+sd-jwt".
const TypeHeader = "dc+sd-jwt"

// SelectiveDisclosureMode defines how a claim should be handled for selective disclosure.
// Per Section 9.2.4, values are: "always", "allowed", or "never".
type SelectiveDisclosureMode string

const (
	// SDAlways means the claim is always selectively disclosable.
	SDAlways SelectiveDisclosureMode = "always"
	// SDAllowed means the claim may be selectively disclosable at issuer's discretion.
	SDAllowed SelectiveDisclosureMode = "allowed"
	// SDNever means the claim is never selectively disclosable.
	SDNever SelectiveDisclosureMode = "never"
)

// ClaimsNotSelectivelyDisclosable are claims that MUST NOT be selectively disclosed
// per Section 3.2.2.2 of the specification.
var ClaimsNotSelectivelyDisclosable = []string{
	"iss",           // Issuer (optional in SD-JWT VC per spec)
	"nbf",           // Not Before
	"exp",           // Expiration
	"cnf",           // Confirmation (holder key binding)
	"vct",           // Verifiable Credential Type (REQUIRED)
	"vct#integrity", // VCT integrity hash
	"status",        // Status information (revocation)
}

// ClaimsMayBeSelectivelyDisclosed are claims that MAY be selectively disclosed
// per Section 3.2.2.2 of the specification.
var ClaimsMayBeSelectivelyDisclosed = []string{
	"sub", // Subject
	"iat", // Issued At
}

// VCPayload represents the payload of an SD-JWT VC as defined in Section 3.2.2.
type VCPayload struct {
	// Issuer is the issuer of the VC (OPTIONAL per spec, but recommended)
	// If present, MUST NOT be selectively disclosed.
	Issuer string `json:"iss,omitempty"`

	// Subject is the subject of the VC (OPTIONAL)
	// MAY be selectively disclosed.
	Subject string `json:"sub,omitempty"`

	// IssuedAt is when the VC was issued (OPTIONAL)
	// MAY be selectively disclosed.
	IssuedAt int64 `json:"iat,omitempty"`

	// NotBefore is the time before which the VC is not valid (OPTIONAL)
	// MUST NOT be selectively disclosed.
	NotBefore int64 `json:"nbf,omitempty"`

	// ExpirationTime is when the VC expires (OPTIONAL)
	// MUST NOT be selectively disclosed.
	ExpirationTime int64 `json:"exp,omitempty"`

	// VCT is the Verifiable Credential Type URI (REQUIRED)
	// MUST NOT be selectively disclosed.
	VCT string `json:"vct"`

	// VCTIntegrity is the cryptographic hash of the VCT document (OPTIONAL)
	// Used to ensure integrity of the type metadata.
	// MUST NOT be selectively disclosed.
	VCTIntegrity string `json:"vct#integrity,omitempty"`

	// CNF is the confirmation claim for key binding (OPTIONAL)
	// MUST NOT be selectively disclosed.
	CNF *sdjwt.CNFClaim `json:"cnf,omitempty"`

	// Status contains status/revocation information (OPTIONAL)
	// MUST NOT be selectively disclosed.
	Status *VCStatus `json:"status,omitempty"`

	// Extra contains additional application-specific claims
	Extra map[string]any `json:"-"`
}

// VCStatus represents the status claim in an SD-JWT VC per Section 3.2.2.1.
type VCStatus struct {
	// StatusList contains status list reference per draft-ietf-oauth-status-list
	StatusList *StatusListReference `json:"status_list,omitempty"`
}

// StatusListReference references a status list entry per draft-ietf-oauth-status-list.
type StatusListReference struct {
	// Index is the index in the status list (idx)
	Index int `json:"idx"`
	// URI is the URI of the status list token
	URI string `json:"uri"`
}

// VCTMetadata represents Verifiable Credential Type metadata as defined in Section 6.2.
// This metadata describes the structure and semantics of a credential type.
type VCTMetadata struct {
	// VCT is the VC type identifier (REQUIRED)
	// This is the same value used in the vct claim.
	VCT string `json:"vct"`

	// Name is the human-readable name of the VC type (OPTIONAL)
	Name string `json:"name,omitempty"`

	// Description describes the VC type (OPTIONAL)
	Description string `json:"description,omitempty"`

	// Extends lists VCT URIs that this type extends (OPTIONAL).
	// Per the spec, this SHOULD contain at most one entry.
	Extends []string `json:"extends,omitempty"`

	// ExtendsIntegrity contains integrity hashes for the extended types (OPTIONAL).
	// Per the spec, this SHOULD contain at most one entry.
	ExtendsIntegrity []string `json:"extends#integrity,omitempty"`

	// Display contains localized display information (OPTIONAL)
	// Per Section 8.
	Display []DisplayMetadata `json:"display,omitempty"`

	// Claims describes the claims in this VC type (OPTIONAL)
	// Per Section 9.
	Claims []ClaimMetadata `json:"claims,omitempty"`

	// Schema is the JSON Schema URI for validating the VC claims (OPTIONAL)
	Schema string `json:"schema,omitempty"`

	// SchemaIntegrity is the integrity hash of the schema document (OPTIONAL)
	SchemaIntegrity string `json:"schema#integrity,omitempty"`
}

// DisplayMetadata contains localized display information as defined in Section 8.
type DisplayMetadata struct {
	// Locale is the BCP47 language tag (e.g., "en-US", "de-DE") (OPTIONAL)
	// If omitted, this is the default display information.
	Locale string `json:"locale,omitempty"`

	// Name is the localized human-readable name (OPTIONAL)
	Name string `json:"name,omitempty"`

	// Label is the localized human-readable label for claim display (OPTIONAL)
	// Used by claim display metadata (Section 9.2).
	Label string `json:"label,omitempty"`

	// Description is the localized description (OPTIONAL)
	Description string `json:"description,omitempty"`

	// Rendering contains rendering hints for displaying the credential (OPTIONAL)
	// Per Section 8.1.
	Rendering *RenderingMetadata `json:"rendering,omitempty"`
}

// RenderingMetadata contains rendering hints as defined in Section 8.1.
type RenderingMetadata struct {
	// Simple contains simple rendering properties (OPTIONAL)
	Simple *SimpleRendering `json:"simple,omitempty"`

	// SVGTemplates contains SVG template references (OPTIONAL)
	SVGTemplates []SVGTemplate `json:"svg_templates,omitempty"`
}

// SimpleRendering contains simple rendering properties per Section 8.1.1.
type SimpleRendering struct {
	// Logo is the URI of the credential logo (OPTIONAL)
	Logo *LogoMetadata `json:"logo,omitempty"`

	// BackgroundImage is the URI of the credential background image (OPTIONAL)
	BackgroundImage *BackgroundImageMetadata `json:"background_image,omitempty"`

	// BackgroundColor is the background color in CSS format (OPTIONAL)
	// e.g., "#FFFFFF" or "rgb(255,255,255)"
	BackgroundColor string `json:"background_color,omitempty"`

	// TextColor is the text color in CSS format (OPTIONAL)
	TextColor string `json:"text_color,omitempty"`
}

// LogoMetadata contains logo information per Section 8.1.1.
type LogoMetadata struct {
	// URI is the URI of the logo image (REQUIRED)
	URI string `json:"uri"`

	// URIIntegrity is the integrity hash of the logo (OPTIONAL)
	URIIntegrity string `json:"uri#integrity,omitempty"`

	// AltText is the alternative text for the logo (OPTIONAL)
	AltText string `json:"alt_text,omitempty"`
}

// BackgroundImageMetadata contains background image information per Section 8.1.1.2.
type BackgroundImageMetadata struct {
	// URI is the URI of the background image (REQUIRED)
	URI string `json:"uri"`

	// URIIntegrity is the integrity hash of the image (OPTIONAL)
	URIIntegrity string `json:"uri#integrity,omitempty"`
}

// SVGTemplate represents an SVG template reference per Section 8.1.2.
type SVGTemplate struct {
	// URI is the URI of the SVG template (REQUIRED)
	URI string `json:"uri"`

	// URIIntegrity is the integrity hash of the SVG template (OPTIONAL)
	URIIntegrity string `json:"uri#integrity,omitempty"`

	// Properties contains template-specific properties (OPTIONAL)
	Properties map[string]any `json:"properties,omitempty"`
}

// ClaimMetadata describes a claim in a VCT as defined in Section 9.
type ClaimMetadata struct {
	// Path is the claim path using the claim path format (REQUIRED)
	// Per Section 9.1, this is an array where elements are:
	// - string: object property name
	// - null: any property or array element
	// - integer: specific array index
	// Examples: ["address", "street_address"], ["nationalities", null]
	Path ClaimPath `json:"path"`

	// Display contains localized display info for this claim (OPTIONAL)
	Display []DisplayMetadata `json:"display,omitempty"`

	// Mandatory indicates whether this claim is mandatory (OPTIONAL)
	// If true, the claim MUST be present in the credential.
	// Default is false.
	Mandatory bool `json:"mandatory,omitempty"`

	// SD indicates selective disclosure requirements (OPTIONAL)
	// Values: "always", "allowed", "never"
	// Default is "allowed".
	SD SelectiveDisclosureMode `json:"sd,omitempty"`

	// SVGID is the identifier for this claim in SVG templates (OPTIONAL)
	// Used when rendering credentials with SVG templates.
	SVGID string `json:"svg_id,omitempty"`
}

// ClaimPath represents a claim path as defined in Section 9.1.
// Elements can be:
// - string: property name
// - nil: wildcard (any property or array element)
// - int: array index
type ClaimPath []any

// String returns a human-readable representation of the claim path.
func (cp ClaimPath) String() string {
	if len(cp) == 0 {
		return ""
	}
	result := ""
	for i, elem := range cp {
		if i > 0 {
			result += "."
		}
		switch v := elem.(type) {
		case string:
			result += v
		case nil:
			result += "*"
		case int:
			result += fmt.Sprintf("[%d]", v)
		case float64:
			result += fmt.Sprintf("[%d]", int(v))
		default:
			result += fmt.Sprintf("%v", v)
		}
	}
	return result
}

// NewClaimPath creates a ClaimPath from variadic arguments.
// Use nil for wildcard matching.
func NewClaimPath(elements ...any) ClaimPath {
	return ClaimPath(elements)
}

// IssuerConfig contains configuration for a VC issuer.
type IssuerConfig struct {
	// IssuerID is the issuer identifier (iss claim) (OPTIONAL but recommended)
	IssuerID string

	// Signer is the signer for signing JWTs (REQUIRED).
	Signer signer.Signer

	// HashAlgorithm is the hash algorithm for disclosures (default: sha-256)
	HashAlgorithm string
}

// VCIssuer creates SD-JWT VCs conformant to draft-ietf-oauth-sd-jwt-vc-13.
type VCIssuer struct {
	config IssuerConfig
	issuer *issuer.Issuer
}

// NewVCIssuer creates a new VC issuer with the given configuration.
func NewVCIssuer(config IssuerConfig) (*VCIssuer, error) {
	if config.Signer == nil {
		return nil, fmt.Errorf("signer is required for VC issuer")
	}
	iss := issuer.NewIssuer(config.Signer)
	return &VCIssuer{
		config: config,
		issuer: iss,
	}, nil
}

// NewVCIssuerWithSigner creates a new VC issuer with a custom signer.
// This is a convenience constructor for when using an external signing service.
func NewVCIssuerWithSigner(issuerID string, s signer.Signer, hashAlgorithm string) (*VCIssuer, error) {
	return NewVCIssuer(IssuerConfig{
		IssuerID:      issuerID,
		Signer:        s,
		HashAlgorithm: hashAlgorithm,
	})
}

// VCIssueOptions contains options for issuing a VC.
type VCIssueOptions struct {
	// VCT is the Verifiable Credential Type URI (REQUIRED)
	VCT string

	// VCTIntegrity is the cryptographic hash of the VCT document (OPTIONAL)
	// Format: "<hash-algorithm>-<base64url-encoded-hash>"
	VCTIntegrity string

	// Subject is the subject of the VC (OPTIONAL)
	Subject string

	// IssuedAt is when the VC was issued (defaults to now) (OPTIONAL)
	IssuedAt *time.Time

	// NotBefore is when the VC becomes valid (OPTIONAL)
	NotBefore *time.Time

	// ExpirationTime is when the VC expires (OPTIONAL)
	ExpirationTime *time.Time

	// HolderPublicKey is the holder's public key for key binding in JWK format (OPTIONAL)
	HolderPublicKey json.RawMessage

	// Status is the status reference for revocation (OPTIONAL)
	Status *StatusListReference

	// DecoyDigests is the number of decoy digests to add (OPTIONAL)
	// Decoy digests help hide the structure of the credential.
	DecoyDigests int
}

// Issue creates an SD-JWT VC from a disclosure frame and claims.
// The claims map should contain the credential subject claims.
// The frame specifies which claims should be selectively disclosable.
//
// Per Section 3.2.2.2, certain claims MUST NOT be selectively disclosed:
// iss, nbf, exp, cnf, vct, vct#integrity, status
//
// Claims sub and iat MAY be selectively disclosed.
func (v *VCIssuer) Issue(claims map[string]any, frame *sdjwt.DisclosureFrame, opts VCIssueOptions) (*sdjwt.SDJWT, error) {
	// Validate required fields
	if opts.VCT == "" {
		return nil, fmt.Errorf("VCT (Verifiable Credential Type) is required per Section 3.2.2")
	}
	if opts.VCTIntegrity != "" {
		if err := validateIntegrityMetadata(opts.VCTIntegrity); err != nil {
			return nil, fmt.Errorf("invalid vct#integrity: %w", err)
		}
	}
	if opts.Status != nil {
		if opts.Status.Index < 0 {
			return nil, fmt.Errorf("status_list idx must be non-negative")
		}
		if opts.Status.URI == "" {
			return nil, fmt.Errorf("status_list uri is required")
		}
	}

	// Build the full payload
	payload := make(map[string]any)

	// Copy user claims
	for k, val := range claims {
		payload[k] = val
	}

	// Add required/optional claims per Section 3.2.2
	if v.config.IssuerID != "" {
		payload["iss"] = v.config.IssuerID
	}
	payload["vct"] = opts.VCT

	if opts.VCTIntegrity != "" {
		payload["vct#integrity"] = opts.VCTIntegrity
	}

	if opts.Subject != "" {
		payload["sub"] = opts.Subject
	}

	now := time.Now()
	if opts.IssuedAt != nil {
		payload["iat"] = opts.IssuedAt.Unix()
	} else {
		payload["iat"] = now.Unix()
	}

	if opts.NotBefore != nil {
		payload["nbf"] = opts.NotBefore.Unix()
	}

	if opts.ExpirationTime != nil {
		payload["exp"] = opts.ExpirationTime.Unix()
	}

	if opts.HolderPublicKey != nil {
		var jwk map[string]any
		if err := json.Unmarshal(opts.HolderPublicKey, &jwk); err != nil {
			return nil, fmt.Errorf("invalid holder public key JWK: %w", err)
		}
		payload["cnf"] = map[string]any{
			"jwk": jwk,
		}
	}

	if opts.Status != nil {
		payload["status"] = map[string]any{
			"status_list": map[string]any{
				"idx": opts.Status.Index,
				"uri": opts.Status.URI,
			},
		}
	}

	// Issue using frame-based API with the SD-JWT VC type header
	issueOpts := &issuer.IssueOptions{
		HashAlgorithm: v.config.HashAlgorithm,
		Type:          TypeHeader, // Set typ to "dc+sd-jwt" per Section 3.2.1
	}

	// Add decoy digests to frame if specified
	if frame == nil {
		frame = &sdjwt.DisclosureFrame{}
	}
	if err := validateSDFrameTopLevel(frame); err != nil {
		return nil, err
	}
	if !frameHasSDClaims(frame) && frameHasDecoys(frame) {
		return nil, fmt.Errorf("decoy digests are not allowed when no claims are selectively disclosable")
	}
	if opts.DecoyDigests > 0 {
		if !frameHasSDClaims(frame) {
			return nil, fmt.Errorf("decoy digests require at least one selectively disclosable claim")
		}
		frame.SDDecoy = opts.DecoyDigests
	}

	return v.issuer.IssueWithFrame(payload, frame, issueOpts)
}

// ValidationOptions contains options for VC validation.
type ValidationOptions struct {
	// SkipExpirationCheck skips the expiration time check
	SkipExpirationCheck bool

	// SkipNotBeforeCheck skips the not-before time check
	SkipNotBeforeCheck bool

	// AllowedClockSkew is the allowed clock skew for time validation
	AllowedClockSkew time.Duration

	// Now overrides the current time for validation (useful for testing)
	Now *time.Time
}

// ValidateVC validates a VC payload against SD-JWT VC requirements per Section 3.4.
// This performs structural validation of the claims.
func ValidateVC(payload map[string]any) error {
	return ValidateVCWithOptions(payload, nil)
}

// ValidateVCWithOptions validates a VC payload with custom options.
func ValidateVCWithOptions(payload map[string]any, opts *ValidationOptions) error {
	if opts == nil {
		opts = &ValidationOptions{}
	}

	now := time.Now()
	if opts.Now != nil {
		now = *opts.Now
	}
	nowUnix := now.Unix()

	// vct is REQUIRED per Section 3.2.2
	if _, ok := payload["vct"]; !ok {
		return fmt.Errorf("missing required claim: vct (per Section 3.2.2)")
	}

	// Validate vct is a non-empty string
	if vct, ok := payload["vct"].(string); !ok || vct == "" {
		return fmt.Errorf("vct must be a non-empty string (per Section 3.2.2)")
	}

	if vctIntegrity, ok := payload["vct#integrity"]; ok {
		vs, ok := vctIntegrity.(string)
		if !ok || vs == "" {
			return fmt.Errorf("vct#integrity must be a non-empty string")
		}
		if err := validateIntegrityMetadata(vs); err != nil {
			return fmt.Errorf("invalid vct#integrity: %w", err)
		}
	}

	// iss is OPTIONAL per the spec, but if present, validate it
	if iss, exists := payload["iss"]; exists {
		if issStr, ok := iss.(string); !ok || issStr == "" {
			return fmt.Errorf("iss, if present, must be a non-empty string")
		}
	}

	if cnfRaw, ok := payload["cnf"]; ok {
		if err := validateCNFClaim(cnfRaw); err != nil {
			return err
		}
	}

	if statusRaw, ok := payload["status"]; ok {
		if err := validateStatusClaim(statusRaw); err != nil {
			return err
		}
	}

	// Validate time claims if present
	if !opts.SkipNotBeforeCheck {
		if nbf, ok := payload["nbf"]; ok {
			nbfTime, err := toInt64(nbf)
			if err != nil {
				return fmt.Errorf("nbf must be a number: %w", err)
			}
			if nbfTime > nowUnix+int64(opts.AllowedClockSkew.Seconds()) {
				return fmt.Errorf("VC not yet valid (nbf: %d, now: %d)", nbfTime, nowUnix)
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
				return fmt.Errorf("VC has expired (exp: %d, now: %d)", expTime, nowUnix)
			}
		}
	}

	return nil
}

// CheckStatus checks the revocation status of a VC using a status list.
// Returns true if the credential is valid (not revoked), false otherwise.
func CheckStatus(payload map[string]any, statusListToken *statuslist.StatusListToken, listSize int) (bool, error) {
	// Get status claim
	statusClaim, ok := payload["status"]
	if !ok {
		// No status claim - credential doesn't support status checking
		// Per spec, this means the credential is always considered valid for status purposes
		return true, nil
	}

	statusMap, ok := statusClaim.(map[string]any)
	if !ok {
		return false, fmt.Errorf("invalid status claim format")
	}

	statusListClaim, ok := statusMap["status_list"]
	if !ok {
		return false, fmt.Errorf("missing status_list in status claim")
	}

	statusListRef, ok := statusListClaim.(map[string]any)
	if !ok {
		return false, fmt.Errorf("invalid status_list format")
	}

	// Get index
	idx, err := toInt64(statusListRef["idx"])
	if err != nil {
		return false, fmt.Errorf("invalid status_list index: %w", err)
	}

	// Get the status list
	sl, err := statusListToken.GetStatusList(listSize)
	if err != nil {
		return false, fmt.Errorf("failed to decode status list: %w", err)
	}

	// Check status
	status, err := sl.GetStatus(int(idx))
	if err != nil {
		return false, fmt.Errorf("failed to get status at index %d: %w", idx, err)
	}

	// Status 0 = valid, anything else = revoked/invalid
	return status == statuslist.StatusValid, nil
}

// toInt64 converts a JSON number to int64.
func toInt64(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}

// IsClaimSelectivelyDisclosable checks if a claim can be selectively disclosed
// per Section 3.2.2.2.
func IsClaimSelectivelyDisclosable(name string) bool {
	for _, claim := range ClaimsNotSelectivelyDisclosable {
		if name == claim {
			return false
		}
	}
	return true
}

// MustNotBeSelectivelyDisclosed checks if a claim MUST NOT be selectively disclosed
// per Section 3.2.2.2.
func MustNotBeSelectivelyDisclosed(name string) bool {
	for _, claim := range ClaimsNotSelectivelyDisclosable {
		if name == claim {
			return true
		}
	}
	return false
}

// MayBeSelectivelyDisclosed checks if a claim MAY be selectively disclosed
// per Section 3.2.2.2.
func MayBeSelectivelyDisclosed(name string) bool {
	for _, claim := range ClaimsMayBeSelectivelyDisclosed {
		if name == claim {
			return true
		}
	}
	// All claims not in the "must not" list may be selectively disclosed
	return !MustNotBeSelectivelyDisclosed(name)
}

// GetClaimsNotSelectivelyDisclosable returns the list of claims that MUST NOT
// be selectively disclosed.
func GetClaimsNotSelectivelyDisclosable() []string {
	result := make([]string, len(ClaimsNotSelectivelyDisclosable))
	copy(result, ClaimsNotSelectivelyDisclosable)
	return result
}
