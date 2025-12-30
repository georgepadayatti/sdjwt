package sdjwtvc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/statuslist"
	"github.com/georgepadayatti/sdjwt/verifier"
)

// VCVerificationOptions controls SD-JWT VC verification behavior.
type VCVerificationOptions struct {
	// Verifier is an optional preconfigured verifier.
	Verifier *verifier.Verifier

	// Validation provides claim validation options (vct, time checks, etc.).
	Validation *ValidationOptions

	// CheckStatus enables status list verification when a status claim is present.
	CheckStatus bool

	// StatusListToken is the status list token used when CheckStatus is true.
	StatusListToken *statuslist.StatusListToken

	// StatusListSize is the size of the status list used for verification.
	StatusListSize int
}

// VerifySDJWTVC verifies an SD-JWT VC without key binding.
func VerifySDJWTVC(serialized string, issuerSigner signer.Signer, requiredClaims *sdjwt.PresentationFrame, opts *VCVerificationOptions) (*verifier.VerificationResult, error) {
	v, err := resolveVerifier(issuerSigner, opts)
	if err != nil {
		return nil, err
	}

	result, err := v.Verify(serialized, requiredClaims)
	if err != nil {
		return result, err
	}

	if err := enforceVCTyp(serialized); err != nil {
		result.AddError(fmt.Sprintf("typ header validation failed: %v", err))
		result.Valid = false
		return result, err
	}

	if err := ValidateVCWithOptions(result.ProcessedPayload, validationOptions(opts)); err != nil {
		result.AddError(fmt.Sprintf("vc payload validation failed: %v", err))
		result.Valid = false
		return result, err
	}

	if err := checkVCStatus(result.ProcessedPayload, opts); err != nil {
		result.AddError(fmt.Sprintf("status validation failed: %v", err))
		result.Valid = false
		return result, err
	}

	if len(result.Errors) == 0 && len(result.MissingRequired) == 0 {
		result.Valid = true
	}

	return result, nil
}

// VerifySDJWTVCWithKeyBinding verifies an SD-JWT VC with key binding.
func VerifySDJWTVCWithKeyBinding(serialized string, issuerSigner signer.Signer, requiredClaims *sdjwt.PresentationFrame, keyBinding *verifier.KeyBindingRequirement, opts *VCVerificationOptions) (*verifier.VerificationResult, error) {
	v, err := resolveVerifier(issuerSigner, opts)
	if err != nil {
		return nil, err
	}

	result, err := v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
	if err != nil {
		return result, err
	}

	if err := enforceVCTyp(serialized); err != nil {
		result.AddError(fmt.Sprintf("typ header validation failed: %v", err))
		result.Valid = false
		return result, err
	}

	if err := ValidateVCWithOptions(result.ProcessedPayload, validationOptions(opts)); err != nil {
		result.AddError(fmt.Sprintf("vc payload validation failed: %v", err))
		result.Valid = false
		return result, err
	}

	if err := checkVCStatus(result.ProcessedPayload, opts); err != nil {
		result.AddError(fmt.Sprintf("status validation failed: %v", err))
		result.Valid = false
		return result, err
	}

	if len(result.Errors) == 0 && len(result.MissingRequired) == 0 && result.KeyBindingValid != nil && *result.KeyBindingValid {
		result.Valid = true
	}

	return result, nil
}

func resolveVerifier(issuerSigner signer.Signer, opts *VCVerificationOptions) (*verifier.Verifier, error) {
	if opts != nil && opts.Verifier != nil {
		return opts.Verifier, nil
	}
	if issuerSigner == nil {
		return nil, fmt.Errorf("issuer signer is required for verification")
	}
	return verifier.NewVerifier(issuerSigner), nil
}

func validationOptions(opts *VCVerificationOptions) *ValidationOptions {
	if opts == nil {
		return nil
	}
	return opts.Validation
}

func enforceVCTyp(serialized string) error {
	sdj, _, err := sdjwt.Parse(serialized, "")
	if err != nil {
		return err
	}
	return validateTypeHeader(sdj.IssuerSignedJWT)
}

func validateTypeHeader(jwtString string) error {
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}
	headerBytes, err := sdjwt.Base64URLDecode(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}
	typ, ok := header["typ"].(string)
	if !ok || typ != TypeHeader {
		return fmt.Errorf("typ must be %q", TypeHeader)
	}
	return nil
}

func checkVCStatus(payload map[string]any, opts *VCVerificationOptions) error {
	if opts == nil || !opts.CheckStatus {
		return nil
	}
	if _, ok := payload["status"]; !ok {
		return nil
	}
	if opts.StatusListToken == nil {
		return fmt.Errorf("status list token is required when status checking is enabled")
	}
	if opts.StatusListSize <= 0 {
		return fmt.Errorf("status list size must be positive when status checking is enabled")
	}
	valid, err := CheckStatus(payload, opts.StatusListToken, opts.StatusListSize)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("credential is revoked or invalid per status list")
	}
	return nil
}
