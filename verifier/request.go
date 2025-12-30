// Package verifier provides functionality for verifying SD-JWTs and SD-JWT+KBs.
package verifier

// KeyBindingRequirement specifies key binding verification requirements.
// This is provided by the verifier to:
// 1. The holder - to craft the Key Binding JWT with the correct audience and nonce
// 2. Themselves - to verify the Key Binding JWT in the received presentation
type KeyBindingRequirement struct {
	// Nonce is the expected nonce value in the KB-JWT (required)
	// This should be a unique random value for each presentation request
	Nonce string `json:"nonce"`

	// Audience is the expected audience value in the KB-JWT (required)
	// This should be the verifier's identifier
	Audience string `json:"audience"`

	// MaxAge is the maximum age in seconds for the KB-JWT iat claim
	// If 0, no age check is performed
	MaxAge int64 `json:"max_age,omitempty"`
}

// Validate checks if the key binding requirement is valid.
func (r *KeyBindingRequirement) Validate() error {
	if r.Nonce == "" {
		return ErrNonceRequired
	}
	if r.Audience == "" {
		return ErrAudienceRequired
	}
	return nil
}

// VerificationResult contains the result of SD-JWT verification.
type VerificationResult struct {
	// Valid indicates whether the verification succeeded
	Valid bool `json:"valid"`

	// ProcessedPayload contains the disclosed claims after processing
	ProcessedPayload map[string]any `json:"processed_payload,omitempty"`

	// DisclosedClaims lists the names of claims that were disclosed
	DisclosedClaims []string `json:"disclosed_claims,omitempty"`

	// MissingRequired lists required claims that were not disclosed
	MissingRequired []string `json:"missing_required,omitempty"`

	// KeyBindingValid indicates whether key binding verification succeeded
	// Only set when key binding was verified
	KeyBindingValid *bool `json:"key_binding_valid,omitempty"`

	// Errors contains any error messages
	Errors []string `json:"errors,omitempty"`
}

// AddError adds an error message to the result.
func (r *VerificationResult) AddError(msg string) {
	r.Errors = append(r.Errors, msg)
}

// IsComplete returns true if all required claims are present.
func (r *VerificationResult) IsComplete() bool {
	return len(r.MissingRequired) == 0
}

// HasClaim checks if a specific claim was disclosed.
func (r *VerificationResult) HasClaim(name string) bool {
	for _, c := range r.DisclosedClaims {
		if c == name {
			return true
		}
	}
	return false
}

// GetClaim retrieves a specific claim value from the processed payload.
func (r *VerificationResult) GetClaim(name string) (any, bool) {
	if r.ProcessedPayload == nil {
		return nil, false
	}
	val, ok := r.ProcessedPayload[name]
	return val, ok
}
