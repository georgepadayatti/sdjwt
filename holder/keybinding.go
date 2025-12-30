package holder

import (
	"fmt"
	"time"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/golang-jwt/jwt/v5"
)

// KeyBindingOptions contains options for creating a Key Binding JWT.
// These options are typically derived from a verifier's KeyBindingRequirement.
type KeyBindingOptions struct {
	// Audience is the intended verifier (required for key binding)
	// This should match the verifier's identifier
	Audience string

	// Nonce is a random value for replay protection (required for key binding)
	// This should be the nonce provided by the verifier
	Nonce string

	// IssuedAt is the time the KB-JWT was created (defaults to now)
	IssuedAt time.Time
}

// NewKeyBindingOptions creates KeyBindingOptions from a verifier's nonce and audience.
// This is the primary way to create KeyBindingOptions from a verifier's request.
func NewKeyBindingOptions(audience, nonce string) KeyBindingOptions {
	return KeyBindingOptions{
		Audience: audience,
		Nonce:    nonce,
		IssuedAt: time.Now(),
	}
}

// CreateKeyBindingJWT creates a Key Binding JWT using a signer.
func CreateKeyBindingJWT(
	sdj *sdjwt.SDJWT,
	s signer.Signer,
	opts KeyBindingOptions,
) (string, error) {
	if s == nil {
		return "", fmt.Errorf("signer is required for key binding JWT")
	}
	// Validate options
	if opts.Audience == "" {
		return "", fmt.Errorf("audience is required for key binding JWT")
	}
	if opts.Nonce == "" {
		return "", fmt.Errorf("nonce is required for key binding JWT")
	}

	// Set default issued at time
	issuedAt := opts.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}

	// Compute the sd_hash over the SD-JWT string
	sdJWTString := sdj.Serialize()
	sdHash, err := sdjwt.HashSDJWT(sdJWTString, sdj.HashAlgorithm)
	if err != nil {
		return "", fmt.Errorf("failed to compute sd_hash: %w", err)
	}

	// Create the KB-JWT payload
	claims := jwt.MapClaims{
		"iat":     issuedAt.Unix(),
		"aud":     opts.Audience,
		"nonce":   opts.Nonce,
		"sd_hash": sdHash,
	}

	// Create the token with the required type header using the Signer's adapter
	signingMethod := signer.NewSigningMethod(s)
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = sdjwt.KBJWTType

	// Sign the token (key is nil since Signer manages its own key)
	signedJWT, err := token.SignedString(nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign key binding JWT: %w", err)
	}

	return signedJWT, nil
}

// SerializePresentation serializes an SD-JWT+KB to a string.
func SerializePresentation(presentation *sdjwt.SDJWTWithKB) string {
	return presentation.Serialize()
}

// SerializeSDJWT serializes an SD-JWT (without KB) to a string.
func SerializeSDJWT(sdj *sdjwt.SDJWT) string {
	return sdj.Serialize()
}
