package verifier

import "errors"

var (
	// ErrNonceRequired is returned when nonce is required but not provided.
	ErrNonceRequired = errors.New("nonce is required for key binding")

	// ErrAudienceRequired is returned when audience is required but not provided.
	ErrAudienceRequired = errors.New("audience is required for key binding")

	// ErrKeyBindingRequired is returned when key binding is required but not provided.
	ErrKeyBindingRequired = errors.New("key binding is required but not provided")

	// ErrKeyBindingMissing is returned when key binding JWT is missing.
	ErrKeyBindingMissing = errors.New("key binding JWT is required but not present")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("signature verification failed")

	// ErrMissingRequiredClaims is returned when required claims are missing.
	ErrMissingRequiredClaims = errors.New("missing required claims")
)
