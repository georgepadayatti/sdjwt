package sdjwt

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
)

// Supported hash algorithms per IANA registry
const (
	HashAlgSHA256 = "sha-256"
	HashAlgSHA384 = "sha-384"
	HashAlgSHA512 = "sha-512"
)

// HashDisclosure computes the digest of a disclosure string using the specified algorithm.
// The input should be the base64url-encoded disclosure string.
// Returns the base64url-encoded digest.
func HashDisclosure(disclosure string, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = DefaultHashAlgorithm
	}

	switch algorithm {
	case HashAlgSHA256:
		return hashSHA256(disclosure), nil
	case HashAlgSHA384:
		return hashSHA384(disclosure), nil
	case HashAlgSHA512:
		return hashSHA512(disclosure), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// hashSHA256 computes SHA-256 hash of the input string and returns base64url-encoded result.
// Per RFC 9901, the hash is computed over the US-ASCII bytes of the base64url-encoded disclosure.
func hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// hashSHA384 computes SHA-384 hash of the input string and returns base64url-encoded result.
func hashSHA384(input string) string {
	hash := sha512.Sum384([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// hashSHA512 computes SHA-512 hash of the input string and returns base64url-encoded result.
func hashSHA512(input string) string {
	hash := sha512.Sum512([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// HashSDJWT computes the hash of an SD-JWT for use in the sd_hash claim of a KB-JWT.
// The input should be the SD-JWT string (JWT~disclosure1~disclosure2~...~)
func HashSDJWT(sdjwt string, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = DefaultHashAlgorithm
	}

	switch algorithm {
	case HashAlgSHA256:
		return hashSHA256(sdjwt), nil
	case HashAlgSHA384:
		return hashSHA384(sdjwt), nil
	case HashAlgSHA512:
		return hashSHA512(sdjwt), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// IsSupportedHashAlgorithm checks if the given algorithm is supported.
func IsSupportedHashAlgorithm(algorithm string) bool {
	switch algorithm {
	case HashAlgSHA256, HashAlgSHA384, HashAlgSHA512, "":
		return true
	default:
		return false
	}
}

// Base64URLEncode encodes data using base64url encoding without padding.
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes a base64url-encoded string without padding.
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
