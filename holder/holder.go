// Package holder provides functionality for holders to manage and present SD-JWTs.
package holder

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/golang-jwt/jwt/v5"
)

// Holder manages SD-JWTs and creates presentations.
type Holder struct {
	// SDJWT is the SD-JWT received from the issuer
	SDJWT *sdjwt.SDJWT
}

// HolderOptions controls validation behavior when receiving SD-JWTs.
type HolderOptions struct {
	// AllowedAlgorithms restricts accepted JWT signing algorithms.
	// If empty, a default allowlist is used.
	AllowedAlgorithms []string

	// TrustedIssuers is an optional list of trusted issuer identifiers.
	TrustedIssuers []string

	// AllowExpired skips expiration check (for testing only).
	AllowExpired bool

	// ExpectedAudience is an optional audience value to enforce.
	ExpectedAudience string

	// RequireExpiration enforces the presence of exp.
	RequireExpiration bool

	// RequireNotBefore enforces the presence of nbf.
	RequireNotBefore bool

	// RequireAudience enforces the presence of aud.
	RequireAudience bool
}

// NewHolder creates a new Holder with the given SD-JWT.
func NewHolder(sdj *sdjwt.SDJWT) *Holder {
	return &Holder{SDJWT: sdj}
}

// ParseAndCreateHolder parses an SD-JWT string, validates it, and creates a Holder.
func ParseAndCreateHolder(serialized string, issuerSigner signer.Signer, opts *HolderOptions) (*Holder, error) {
	sdj, err := sdjwt.ParseSDJWT(serialized, "")
	if err != nil {
		return nil, err
	}
	if issuerSigner == nil {
		return nil, fmt.Errorf("issuer signer is required")
	}
	if opts == nil {
		opts = &HolderOptions{}
	}

	if err := verifyIssuerJWT(sdj.IssuerSignedJWT, issuerSigner, opts.AllowedAlgorithms); err != nil {
		return nil, err
	}

	payload, err := extractPayload(sdj.IssuerSignedJWT)
	if err != nil {
		return nil, err
	}

	processed, _, err := sdjwt.ProcessSDJWTPayload(payload, sdj.Disclosures, sdj.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	if err := validateProcessedClaims(processed, opts); err != nil {
		return nil, err
	}

	return NewHolder(sdj), nil
}

// GetDisclosureByDigest finds a disclosure by its digest.
func (h *Holder) GetDisclosureByDigest(digest string) *sdjwt.Disclosure {
	return h.SDJWT.FindDisclosureByDigest(digest)
}

// getJWTPayload extracts and parses the JWT payload.
func (h *Holder) getJWTPayload() (map[string]any, error) {
	parts := strings.Split(h.SDJWT.IssuerSignedJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := sdjwt.Base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	return payload, nil
}

// GetProcessedPayload returns the fully processed payload with all claims.
// This is useful for the holder to see what the SD-JWT contains.
func (h *Holder) GetProcessedPayload() (*sdjwt.ProcessedPayload, error) {
	payload, err := h.getJWTPayload()
	if err != nil {
		return nil, err
	}

	// Process the payload with all disclosures (strict RFC 9901 validation)
	processed, _, err := sdjwt.ProcessSDJWTPayload(payload, h.SDJWT.Disclosures, h.SDJWT.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	// Extract CNF if present
	var cnf *sdjwt.CNFClaim
	if cnfRaw, ok := payload["cnf"]; ok {
		cnfBytes, err := json.Marshal(cnfRaw)
		if err == nil {
			cnf = &sdjwt.CNFClaim{}
			json.Unmarshal(cnfBytes, cnf)
		}
	}

	return &sdjwt.ProcessedPayload{
		Claims: processed,
		CNF:    cnf,
	}, nil
}

// GetHolderPublicKey extracts the holder's public key from the SD-JWT.
func (h *Holder) GetHolderPublicKey() (json.RawMessage, error) {
	payload, err := h.getJWTPayload()
	if err != nil {
		return nil, err
	}

	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no confirmation claim (cnf) in SD-JWT")
	}

	jwk, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("no JWK in confirmation claim")
	}

	return json.Marshal(jwk)
}

// VerifyIssuerSignature verifies the issuer's signature on the SD-JWT.
func (h *Holder) VerifyIssuerSignature(issuerSigner signer.Signer) error {
	if issuerSigner == nil {
		return fmt.Errorf("signer is required to verify issuer signature")
	}
	return verifyIssuerJWT(h.SDJWT.IssuerSignedJWT, issuerSigner, nil)
}

func verifyIssuerJWT(jwtString string, issuerSigner signer.Signer, allowedAlgorithms []string) error {
	publicKey := issuerSigner.PublicKey()
	if publicKey == nil {
		return fmt.Errorf("signer does not provide a public key")
	}
	parser := jwt.NewParser(jwt.WithValidMethods(resolveAllowedAlgorithms(allowedAlgorithms)), jwt.WithoutClaimsValidation())
	_, err := parser.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return fmt.Errorf("issuer JWT verification failed: %w", err)
	}
	return nil
}

func extractPayload(jwtString string) (map[string]any, error) {
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := sdjwt.Base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}
	return payload, nil
}

func validateProcessedClaims(payload map[string]any, opts *HolderOptions) error {
	if len(opts.TrustedIssuers) > 0 {
		iss, ok := payload["iss"].(string)
		if !ok {
			return fmt.Errorf("missing issuer claim")
		}
		trusted := false
		for _, ti := range opts.TrustedIssuers {
			if ti == iss {
				trusted = true
				break
			}
		}
		if !trusted {
			return fmt.Errorf("issuer %s is not trusted", iss)
		}
	}

	if exp, ok := payload["exp"].(float64); ok {
		if !opts.AllowExpired && time.Now().Unix() > int64(exp) {
			return fmt.Errorf("JWT has expired")
		}
	} else if opts.RequireExpiration {
		return fmt.Errorf("missing exp claim")
	}

	if nbf, ok := payload["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return fmt.Errorf("JWT is not yet valid")
		}
	} else if opts.RequireNotBefore {
		return fmt.Errorf("missing nbf claim")
	}

	if audRaw, ok := payload["aud"]; ok {
		if opts.ExpectedAudience != "" {
			if !audienceMatches(audRaw, opts.ExpectedAudience) {
				return fmt.Errorf("audience mismatch")
			}
		}
	} else if opts.RequireAudience {
		return fmt.Errorf("missing aud claim")
	}

	return nil
}

func resolveAllowedAlgorithms(allowed []string) []string {
	if len(allowed) > 0 {
		return allowed
	}
	return []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}
}

func audienceMatches(audRaw any, expected string) bool {
	switch aud := audRaw.(type) {
	case string:
		return aud == expected
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range aud {
			if item == expected {
				return true
			}
		}
	}
	return false
}
