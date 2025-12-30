package verifier

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/golang-jwt/jwt/v5"
)

// Verifier verifies SD-JWT and SD-JWT+KB presentations.
type Verifier struct {
	// IssuerSigner is the issuer's signer used to obtain the public key.
	IssuerSigner signer.Signer

	// AllowedAlgorithms restricts accepted JWT signing algorithms.
	// If empty, a default allowlist is used.
	AllowedAlgorithms []string

	// TrustedIssuers is an optional list of trusted issuer identifiers
	TrustedIssuers []string

	// AllowExpired skips expiration check (for testing only)
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

// NewVerifier creates a new Verifier with the given issuer signer.
func NewVerifier(issuerSigner signer.Signer) *Verifier {
	return &Verifier{
		IssuerSigner: issuerSigner,
	}
}

// Verify verifies an SD-JWT presentation without key binding.
// requiredClaims is an optional presentation frame specifying which claims must be disclosed.
func (v *Verifier) Verify(serialized string, requiredClaims *sdjwt.PresentationFrame) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:            false,
		ProcessedPayload: make(map[string]any),
	}

	// Parse the SD-JWT (accept SD-JWT+KB but ignore KB if not required)
	sdj, _, err := sdjwt.Parse(serialized, "")
	if err != nil {
		result.AddError(fmt.Sprintf("failed to parse SD-JWT: %v", err))
		return result, err
	}

	// Verify the issuer signature
	payload, err := v.verifyIssuerSignature(sdj.IssuerSignedJWT)
	if err != nil {
		result.AddError(fmt.Sprintf("issuer signature verification failed: %v", err))
		return result, err
	}

	// Process the payload with disclosures (strict RFC 9901 validation)
	processedPayload, disclosedClaims, err := sdjwt.ProcessSDJWTPayload(payload, sdj.Disclosures, sdj.HashAlgorithm)
	if err != nil {
		result.AddError(fmt.Sprintf("failed to process payload: %v", err))
		return result, err
	}

	result.ProcessedPayload = processedPayload
	result.DisclosedClaims = disclosedClaims

	if err := v.validateProcessedClaims(processedPayload); err != nil {
		result.AddError(fmt.Sprintf("payload validation failed: %v", err))
		return result, err
	}

	// Validate required claims if specified
	if requiredClaims != nil {
		v.validateRequiredClaims(result, requiredClaims)
	}

	// Mark as valid if no errors
	if len(result.Errors) == 0 && len(result.MissingRequired) == 0 {
		result.Valid = true
	}

	return result, nil
}

// VerifyWithKeyBinding verifies an SD-JWT+KB presentation with key binding.
// requiredClaims is an optional presentation frame specifying which claims must be disclosed.
// keyBinding specifies the key binding verification requirements (nonce, audience, max age).
func (v *Verifier) VerifyWithKeyBinding(serialized string, requiredClaims *sdjwt.PresentationFrame, keyBinding *KeyBindingRequirement) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:            false,
		ProcessedPayload: make(map[string]any),
	}

	// Validate key binding requirement
	if keyBinding == nil {
		result.AddError("key binding requirement not specified")
		return result, ErrKeyBindingRequired
	}

	if err := keyBinding.Validate(); err != nil {
		result.AddError(fmt.Sprintf("invalid key binding requirement: %v", err))
		return result, err
	}

	// Parse the SD-JWT+KB
	sdjwtKB, err := sdjwt.ParseSDJWTWithKB(serialized, "")
	if err != nil {
		result.AddError(fmt.Sprintf("failed to parse SD-JWT+KB: %v", err))
		return result, err
	}

	if sdjwtKB.KeyBindingJWT == "" {
		result.AddError("key binding JWT is required but not present")
		return result, ErrKeyBindingMissing
	}

	// Verify the issuer signature
	payload, err := v.verifyIssuerSignature(sdjwtKB.SDJWT.IssuerSignedJWT)
	if err != nil {
		result.AddError(fmt.Sprintf("issuer signature verification failed: %v", err))
		return result, err
	}

	// Process the payload with disclosures (strict RFC 9901 validation)
	processedPayload, disclosedClaims, err := sdjwt.ProcessSDJWTPayload(payload, sdjwtKB.SDJWT.Disclosures, sdjwtKB.SDJWT.HashAlgorithm)
	if err != nil {
		result.AddError(fmt.Sprintf("failed to process payload: %v", err))
		return result, err
	}

	result.ProcessedPayload = processedPayload
	result.DisclosedClaims = disclosedClaims

	// Extract holder's public key from cnf claim
	holderKey, err := extractHolderPublicKey(processedPayload)
	if err != nil {
		result.AddError(fmt.Sprintf("failed to extract holder public key: %v", err))
		return result, err
	}

	// Verify the key binding JWT
	kbValid := false
	err = v.verifyKeyBindingJWT(sdjwtKB, holderKey, keyBinding)
	if err != nil {
		result.AddError(fmt.Sprintf("key binding verification failed: %v", err))
		kbValid = false
	} else {
		kbValid = true
	}
	result.KeyBindingValid = &kbValid

	if err := v.validateProcessedClaims(processedPayload); err != nil {
		result.AddError(fmt.Sprintf("payload validation failed: %v", err))
		return result, err
	}

	// Validate required claims if specified
	if requiredClaims != nil {
		v.validateRequiredClaims(result, requiredClaims)
	}

	// Mark as valid if no errors and key binding is valid
	if len(result.Errors) == 0 && len(result.MissingRequired) == 0 && kbValid {
		result.Valid = true
	}

	return result, nil
}

// verifyIssuerSignature verifies the issuer's JWT signature and returns the payload.
func (v *Verifier) verifyIssuerSignature(jwtString string) (map[string]any, error) {
	if v.IssuerSigner == nil {
		return nil, fmt.Errorf("issuer signer is required for verification")
	}
	publicKey := v.IssuerSigner.PublicKey()
	if publicKey == nil {
		return nil, fmt.Errorf("issuer signer does not provide a public key")
	}
	parser := jwt.NewParser(jwt.WithValidMethods(v.allowedAlgorithms()), jwt.WithoutClaimsValidation())
	token, err := parser.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("JWT is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from JWT")
	}

	return claims, nil
}

// verifyKeyBindingJWT verifies the Key Binding JWT.
func (v *Verifier) verifyKeyBindingJWT(sdjwtKB *sdjwt.SDJWTWithKB, holderKey crypto.PublicKey, req *KeyBindingRequirement) error {
	// Parse and verify the KB-JWT
	parser := jwt.NewParser(jwt.WithValidMethods(v.allowedAlgorithms()))
	token, err := parser.Parse(sdjwtKB.KeyBindingJWT, func(token *jwt.Token) (interface{}, error) {
		// Verify the typ header
		typ, ok := token.Header["typ"].(string)
		if !ok || typ != sdjwt.KBJWTType {
			return nil, fmt.Errorf("invalid KB-JWT typ header: expected %s, got %s", sdjwt.KBJWTType, typ)
		}
		return holderKey, nil
	})

	if err != nil {
		return fmt.Errorf("KB-JWT verification failed: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("KB-JWT is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("failed to extract claims from KB-JWT")
	}

	// Verify sd_hash
	sdHash, ok := claims["sd_hash"].(string)
	if !ok {
		return fmt.Errorf("missing sd_hash claim in KB-JWT")
	}

	// Compute expected sd_hash (over SD-JWT string without KB-JWT)
	sdJWTString := sdjwtKB.SDJWT.Serialize()
	expectedHash, err := sdjwt.HashSDJWT(sdJWTString, sdjwtKB.SDJWT.HashAlgorithm)
	if err != nil {
		return fmt.Errorf("failed to compute sd_hash: %w", err)
	}

	if sdHash != expectedHash {
		return fmt.Errorf("sd_hash mismatch: expected %s, got %s", expectedHash, sdHash)
	}

	// Verify audience
	aud, ok := claims["aud"].(string)
	if !ok {
		return fmt.Errorf("missing aud claim in KB-JWT")
	}
	if req.Audience != "" && aud != req.Audience {
		return fmt.Errorf("audience mismatch: expected %s, got %s", req.Audience, aud)
	}

	// Verify nonce
	nonce, ok := claims["nonce"].(string)
	if !ok {
		return fmt.Errorf("missing nonce claim in KB-JWT")
	}
	if req.Nonce != "" && nonce != req.Nonce {
		return fmt.Errorf("nonce mismatch: expected %s, got %s", req.Nonce, nonce)
	}

	// Verify iat
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("missing iat claim in KB-JWT")
	}

	// Check max age if configured
	if req.MaxAge > 0 {
		age := time.Now().Unix() - int64(iat)
		if age > req.MaxAge {
			return fmt.Errorf("KB-JWT is too old: age %d seconds exceeds max_age %d seconds", age, req.MaxAge)
		}
	}

	return nil
}

func (v *Verifier) validateProcessedClaims(payload map[string]any) error {
	if len(v.TrustedIssuers) > 0 {
		iss, ok := payload["iss"].(string)
		if !ok {
			return fmt.Errorf("missing issuer claim")
		}
		trusted := false
		for _, ti := range v.TrustedIssuers {
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
		if !v.AllowExpired && time.Now().Unix() > int64(exp) {
			return fmt.Errorf("JWT has expired")
		}
	} else if v.RequireExpiration {
		return fmt.Errorf("missing exp claim")
	}

	if nbf, ok := payload["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return fmt.Errorf("JWT is not yet valid")
		}
	} else if v.RequireNotBefore {
		return fmt.Errorf("missing nbf claim")
	}

	if audRaw, ok := payload["aud"]; ok {
		if v.ExpectedAudience != "" {
			if !audMatches(audRaw, v.ExpectedAudience) {
				return fmt.Errorf("audience mismatch")
			}
		}
	} else if v.RequireAudience {
		return fmt.Errorf("missing aud claim")
	}

	return nil
}

func (v *Verifier) allowedAlgorithms() []string {
	if len(v.AllowedAlgorithms) > 0 {
		return v.AllowedAlgorithms
	}
	return []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}
}

func audMatches(audRaw any, expected string) bool {
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

// extractHolderPublicKey extracts the holder's public key from the cnf claim.
func extractHolderPublicKey(payload map[string]any) (crypto.PublicKey, error) {
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid cnf claim")
	}

	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("missing jwk in cnf claim")
	}

	jwkBytes, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Parse the JWK to get the public key
	key, err := parseJWK(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	return key, nil
}

// parseJWK parses a JWK and returns a crypto.PublicKey.
func parseJWK(jwkBytes []byte) (crypto.PublicKey, error) {
	var jwk map[string]any
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK JSON: %w", err)
	}

	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kty in JWK")
	}

	switch kty {
	case "EC":
		return parseECPublicKey(jwk)
	case "RSA":
		return parseRSAPublicKey(jwk)
	case "OKP":
		return parseOKPPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// parseECPublicKey parses an EC JWK to an ECDSA public key.
func parseECPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing crv in EC JWK")
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x in EC JWK")
	}

	y, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing y in EC JWK")
	}

	xBytes, err := sdjwt.Base64URLDecode(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := sdjwt.Base64URLDecode(y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	var curve interface{}
	switch crv {
	case "P-256":
		curve = "P-256"
	case "P-384":
		curve = "P-384"
	case "P-521":
		curve = "P-521"
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	// Use crypto/elliptic to construct the key
	return constructECDSAPublicKey(curve.(string), xBytes, yBytes)
}

// constructECDSAPublicKey constructs an ECDSA public key from curve name and coordinates.
func constructECDSAPublicKey(curveName string, x, y []byte) (crypto.PublicKey, error) {
	var curveSize int
	switch curveName {
	case "P-256":
		curveSize = 32
	case "P-384":
		curveSize = 48
	case "P-521":
		curveSize = 66
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}

	// Pad coordinates to curve size
	xPadded := padBytes(x, curveSize)
	yPadded := padBytes(y, curveSize)

	// Construct a JWK map for parsing
	jwkMap := map[string]interface{}{
		"kty": "EC",
		"crv": curveName,
		"x":   sdjwt.Base64URLEncode(xPadded),
		"y":   sdjwt.Base64URLEncode(yPadded),
	}

	jwkBytes, _ := json.Marshal(jwkMap)

	return parseJWKUsingJWT(jwkBytes)
}

// parseJWKUsingJWT uses manual parsing to convert a JWK to a crypto.PublicKey.
func parseJWKUsingJWT(jwkBytes []byte) (crypto.PublicKey, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, err
	}

	kty, _ := jwk["kty"].(string)

	switch kty {
	case "EC":
		return parseECKey(jwk)
	case "RSA":
		return parseRSAKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// parseECKey parses an EC JWK into an *ecdsa.PublicKey
func parseECKey(jwk map[string]interface{}) (crypto.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)

	xBytes, err := sdjwt.Base64URLDecode(xStr)
	if err != nil {
		return nil, err
	}
	yBytes, err := sdjwt.Base64URLDecode(yStr)
	if err != nil {
		return nil, err
	}

	return buildECDSAKey(crv, xBytes, yBytes)
}

// parseRSAKey parses an RSA JWK
func parseRSAKey(jwk map[string]interface{}) (crypto.PublicKey, error) {
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)

	nBytes, err := sdjwt.Base64URLDecode(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := sdjwt.Base64URLDecode(eStr)
	if err != nil {
		return nil, err
	}

	return buildRSAKey(nBytes, eBytes)
}

// parseRSAPublicKey parses an RSA JWK to an RSA public key.
func parseRSAPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	n, ok := jwk["n"].(string)
	if !ok {
		return nil, fmt.Errorf("missing n in RSA JWK")
	}

	e, ok := jwk["e"].(string)
	if !ok {
		return nil, fmt.Errorf("missing e in RSA JWK")
	}

	nBytes, err := sdjwt.Base64URLDecode(n)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := sdjwt.Base64URLDecode(e)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	return buildRSAKey(nBytes, eBytes)
}

// parseOKPPublicKey parses an OKP JWK (Ed25519).
func parseOKPPublicKey(jwk map[string]any) (crypto.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing crv in OKP JWK")
	}

	if crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x in OKP JWK")
	}

	xBytes, err := sdjwt.Base64URLDecode(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	return buildEd25519Key(xBytes)
}

// padBytes pads a byte slice to the specified length with leading zeros.
func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// validateRequiredClaims validates the verification result against required claims from a presentation frame.
func (v *Verifier) validateRequiredClaims(result *VerificationResult, requiredClaims *sdjwt.PresentationFrame) {
	if requiredClaims == nil {
		return
	}

	// Get all required claim names from the presentation frame
	requiredNames := flattenPresentationFrame(requiredClaims, "")

	// Check each required claim
	for _, required := range requiredNames {
		found := false
		for _, disclosed := range result.DisclosedClaims {
			if disclosed == required || strings.HasPrefix(disclosed, required+".") {
				found = true
				break
			}
		}
		// Also check if the claim exists directly in the payload
		if !found {
			if _, exists := result.ProcessedPayload[required]; exists {
				found = true
			}
		}
		// Check nested claims in processed payload
		if !found {
			found = claimExistsInPayload(result.ProcessedPayload, required)
		}
		if !found {
			result.MissingRequired = append(result.MissingRequired, required)
		}
	}
}

// flattenPresentationFrame converts a presentation frame to a list of claim names.
func flattenPresentationFrame(frame *sdjwt.PresentationFrame, prefix string) []string {
	if frame == nil {
		return nil
	}

	var names []string

	// Add included claims at this level
	for key, include := range frame.Include {
		if include {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			names = append(names, fullKey)
		}
	}

	// Recursively add nested claims
	for key, nestedFrame := range frame.Nested {
		nestedPrefix := key
		if prefix != "" {
			nestedPrefix = prefix + "." + key
		}
		names = append(names, flattenPresentationFrame(nestedFrame, nestedPrefix)...)
	}

	return names
}

// claimExistsInPayload checks if a claim exists in a nested payload.
func claimExistsInPayload(payload map[string]any, claimPath string) bool {
	parts := strings.Split(claimPath, ".")
	current := payload

	for i, part := range parts {
		val, exists := current[part]
		if !exists {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		nested, ok := val.(map[string]any)
		if !ok {
			return false
		}
		current = nested
	}
	return false
}

// VerifySDJWTString is a convenience function for quick verification without key binding.
func VerifySDJWTString(serialized string, issuerSigner signer.Signer, requiredClaims *sdjwt.PresentationFrame) (*VerificationResult, error) {
	v := NewVerifier(issuerSigner)
	return v.Verify(serialized, requiredClaims)
}

// VerifySDJWTWithKBString is a convenience function for quick verification with key binding.
func VerifySDJWTWithKBString(serialized string, issuerSigner signer.Signer, requiredClaims *sdjwt.PresentationFrame, keyBinding *KeyBindingRequirement) (*VerificationResult, error) {
	v := NewVerifier(issuerSigner)
	return v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
}
