package sdjwt

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// SaltLength is the number of random bytes for salt generation.
// 128 bits (16 bytes) is the recommended minimum per RFC 9901.
const SaltLength = 16

// GenerateSalt generates a cryptographically random salt.
// Returns a base64url-encoded string of 128 bits of random data.
func GenerateSalt() (string, error) {
	bytes := make([]byte, SaltLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return Base64URLEncode(bytes), nil
}

// NewDisclosure creates a new disclosure for an object property (name/value pair).
// The disclosure format is: [salt, claim_name, claim_value]
func NewDisclosure(claimName string, claimValue any, hashAlgorithm string) (*Disclosure, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	return NewDisclosureWithSalt(salt, claimName, claimValue, hashAlgorithm)
}

// NewDisclosureWithSalt creates a new disclosure with a specific salt.
// This is useful for testing or when you need deterministic outputs.
func NewDisclosureWithSalt(salt, claimName string, claimValue any, hashAlgorithm string) (*Disclosure, error) {
	// Create the disclosure array: [salt, claim_name, claim_value]
	disclosureArray := []any{salt, claimName, claimValue}

	// JSON encode the array
	jsonBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal disclosure: %w", err)
	}

	// Base64url encode
	encoded := Base64URLEncode(jsonBytes)

	// Compute digest
	digest, err := HashDisclosure(encoded, hashAlgorithm)
	if err != nil {
		return nil, err
	}

	return &Disclosure{
		Salt:         salt,
		ClaimName:    claimName,
		ClaimValue:   claimValue,
		Encoded:      encoded,
		Digest:       digest,
		ArrayElement: false,
	}, nil
}

// NewArrayElementDisclosure creates a new disclosure for an array element.
// The disclosure format is: [salt, value]
func NewArrayElementDisclosure(value any, hashAlgorithm string) (*Disclosure, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	return NewArrayElementDisclosureWithSalt(salt, value, hashAlgorithm)
}

// NewArrayElementDisclosureWithSalt creates a new array element disclosure with a specific salt.
func NewArrayElementDisclosureWithSalt(salt string, value any, hashAlgorithm string) (*Disclosure, error) {
	// Create the disclosure array: [salt, value]
	disclosureArray := []any{salt, value}

	// JSON encode the array
	jsonBytes, err := json.Marshal(disclosureArray)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal disclosure: %w", err)
	}

	// Base64url encode
	encoded := Base64URLEncode(jsonBytes)

	// Compute digest
	digest, err := HashDisclosure(encoded, hashAlgorithm)
	if err != nil {
		return nil, err
	}

	return &Disclosure{
		Salt:         salt,
		ClaimName:    "", // Empty for array elements
		ClaimValue:   value,
		Encoded:      encoded,
		Digest:       digest,
		ArrayElement: true,
	}, nil
}

// ParseDisclosure parses a base64url-encoded disclosure string.
func ParseDisclosure(encoded string, hashAlgorithm string) (*Disclosure, error) {
	// Decode base64url
	jsonBytes, err := Base64URLDecode(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	// Parse JSON array
	var arr []any
	if err := json.Unmarshal(jsonBytes, &arr); err != nil {
		return nil, fmt.Errorf("failed to parse disclosure JSON: %w", err)
	}

	// Compute digest
	digest, err := HashDisclosure(encoded, hashAlgorithm)
	if err != nil {
		return nil, err
	}

	// Check array length to determine type
	switch len(arr) {
	case 2:
		// Array element disclosure: [salt, value]
		salt, ok := arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid disclosure: salt must be a string")
		}
		return &Disclosure{
			Salt:         salt,
			ClaimName:    "",
			ClaimValue:   arr[1],
			Encoded:      encoded,
			Digest:       digest,
			ArrayElement: true,
		}, nil

	case 3:
		// Object property disclosure: [salt, claim_name, claim_value]
		salt, ok := arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid disclosure: salt must be a string")
		}
		claimName, ok := arr[1].(string)
		if !ok {
			return nil, fmt.Errorf("invalid disclosure: claim name must be a string")
		}
		return &Disclosure{
			Salt:         salt,
			ClaimName:    claimName,
			ClaimValue:   arr[2],
			Encoded:      encoded,
			Digest:       digest,
			ArrayElement: false,
		}, nil

	default:
		return nil, fmt.Errorf("invalid disclosure: expected 2 or 3 elements, got %d", len(arr))
	}
}

// GenerateDecoyDigest generates a random decoy digest.
// Decoy digests are used to obscure the actual number of claims.
func GenerateDecoyDigest(hashAlgorithm string) (string, error) {
	// Generate random bytes
	bytes := make([]byte, 32) // 256 bits for SHA-256
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate decoy: %w", err)
	}

	// Hash the random bytes (same process as real disclosures)
	randomStr := Base64URLEncode(bytes)
	return HashDisclosure(randomStr, hashAlgorithm)
}

// ValidateDisclosureClaimName checks if a claim name is valid for use in a disclosure.
// Per RFC 9901, _sd and ... are reserved and cannot be used as claim names.
func ValidateDisclosureClaimName(name string) error {
	if name == "_sd" {
		return fmt.Errorf("claim name '_sd' is reserved")
	}
	if name == "..." {
		return fmt.Errorf("claim name '...' is reserved")
	}
	return nil
}
