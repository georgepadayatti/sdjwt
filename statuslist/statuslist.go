// Package statuslist implements JWT Status List for credential revocation
// as specified in draft-ietf-oauth-status-list.
package statuslist

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/golang-jwt/jwt/v5"
)

// Status values for credentials.
const (
	StatusValid   = 0x00 // Credential is valid
	StatusInvalid = 0x01 // Credential is invalid/revoked
	// Additional status values can be defined for 2-bit and higher encodings
)

// BitsPerStatus defines the number of bits used to represent each status.
type BitsPerStatus int

const (
	// Bits1 uses 1 bit per status (0 or 1)
	Bits1 BitsPerStatus = 1
	// Bits2 uses 2 bits per status (0-3)
	Bits2 BitsPerStatus = 2
	// Bits4 uses 4 bits per status (0-15)
	Bits4 BitsPerStatus = 4
	// Bits8 uses 8 bits per status (0-255)
	Bits8 BitsPerStatus = 8
)

// StatusList represents a compressed bitstring of status values.
type StatusList struct {
	// bits is the raw status values stored as a byte array
	bits []byte
	// bitsPerStatus is how many bits are used per status entry
	bitsPerStatus BitsPerStatus
	// size is the number of status entries
	size int
}

// NewStatusList creates a new StatusList with the specified size and bits per status.
func NewStatusList(size int, bitsPerStatus BitsPerStatus) (*StatusList, error) {
	if size <= 0 {
		return nil, fmt.Errorf("size must be positive")
	}
	if bitsPerStatus != Bits1 && bitsPerStatus != Bits2 && bitsPerStatus != Bits4 && bitsPerStatus != Bits8 {
		return nil, fmt.Errorf("bitsPerStatus must be 1, 2, 4, or 8")
	}

	// Calculate number of bytes needed
	totalBits := size * int(bitsPerStatus)
	numBytes := (totalBits + 7) / 8

	return &StatusList{
		bits:          make([]byte, numBytes),
		bitsPerStatus: bitsPerStatus,
		size:          size,
	}, nil
}

// Size returns the number of status entries.
func (s *StatusList) Size() int {
	return s.size
}

// BitsPerStatus returns the number of bits per status entry.
func (s *StatusList) BitsPerStatus() BitsPerStatus {
	return s.bitsPerStatus
}

// GetStatus returns the status value at the given index.
func (s *StatusList) GetStatus(index int) (int, error) {
	if index < 0 || index >= s.size {
		return 0, fmt.Errorf("index out of range: %d (size: %d)", index, s.size)
	}

	switch s.bitsPerStatus {
	case Bits1:
		byteIndex := index / 8
		bitIndex := uint(index % 8)
		return int((s.bits[byteIndex] >> bitIndex) & 0x01), nil
	case Bits2:
		byteIndex := index / 4
		bitOffset := uint((index % 4) * 2)
		return int((s.bits[byteIndex] >> bitOffset) & 0x03), nil
	case Bits4:
		byteIndex := index / 2
		bitOffset := uint((index % 2) * 4)
		return int((s.bits[byteIndex] >> bitOffset) & 0x0F), nil
	case Bits8:
		return int(s.bits[index]), nil
	}

	return 0, fmt.Errorf("unsupported bitsPerStatus: %d", s.bitsPerStatus)
}

// SetStatus sets the status value at the given index.
func (s *StatusList) SetStatus(index int, value int) error {
	if index < 0 || index >= s.size {
		return fmt.Errorf("index out of range: %d (size: %d)", index, s.size)
	}

	maxValue := (1 << s.bitsPerStatus) - 1
	if value < 0 || value > maxValue {
		return fmt.Errorf("value %d out of range for %d-bit status (max: %d)", value, s.bitsPerStatus, maxValue)
	}

	switch s.bitsPerStatus {
	case Bits1:
		byteIndex := index / 8
		bitIndex := uint(index % 8)
		if value == 1 {
			s.bits[byteIndex] |= (1 << bitIndex)
		} else {
			s.bits[byteIndex] &^= (1 << bitIndex)
		}
	case Bits2:
		byteIndex := index / 4
		bitOffset := uint((index % 4) * 2)
		mask := byte(0x03 << bitOffset)
		s.bits[byteIndex] = (s.bits[byteIndex] &^ mask) | (byte(value) << bitOffset)
	case Bits4:
		byteIndex := index / 2
		bitOffset := uint((index % 2) * 4)
		mask := byte(0x0F << bitOffset)
		s.bits[byteIndex] = (s.bits[byteIndex] &^ mask) | (byte(value) << bitOffset)
	case Bits8:
		s.bits[index] = byte(value)
	}

	return nil
}

// Encode compresses and encodes the status list to a base64url string.
func (s *StatusList) Encode() (string, error) {
	// Compress using DEFLATE
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("failed to create deflate writer: %w", err)
	}

	if _, err := writer.Write(s.bits); err != nil {
		writer.Close()
		return "", fmt.Errorf("failed to compress data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close deflate writer: %w", err)
	}

	// Encode to base64url
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// Decode decodes and decompresses a status list from a base64url string.
func Decode(encoded string, size int, bitsPerStatus BitsPerStatus) (*StatusList, error) {
	// Decode from base64url
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url: %w", err)
	}

	// Decompress using DEFLATE
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	// Calculate expected size
	totalBits := size * int(bitsPerStatus)
	expectedBytes := (totalBits + 7) / 8

	if len(decompressed) < expectedBytes {
		return nil, fmt.Errorf("decompressed data too short: got %d bytes, expected at least %d", len(decompressed), expectedBytes)
	}

	return &StatusList{
		bits:          decompressed[:expectedBytes],
		bitsPerStatus: bitsPerStatus,
		size:          size,
	}, nil
}

// StatusListToken represents the payload of a Status List Token (JWT).
type StatusListToken struct {
	// Issuer is the issuer of the status list token
	Issuer string `json:"iss"`
	// Subject is typically the URI of the status list
	Subject string `json:"sub"`
	// IssuedAt is when the token was issued
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is when the token expires (optional)
	ExpiresAt int64 `json:"exp,omitempty"`
	// TimeToLive is the recommended cache time in seconds
	TimeToLive int64 `json:"ttl,omitempty"`
	// StatusList contains the encoded status list
	StatusList StatusListClaim `json:"status_list"`
}

// StatusListSignOptions contains optional signing settings for status list tokens.
type StatusListSignOptions struct {
	// Type is the JWT typ header value.
	Type string

	// ExtraHeaders contains additional JWT header parameters.
	ExtraHeaders map[string]any
}

// StatusListClaim is the "status_list" claim in a Status List Token.
type StatusListClaim struct {
	// Bits is the number of bits per status (1, 2, 4, or 8)
	Bits int `json:"bits"`
	// List is the base64url-encoded compressed status list
	List string `json:"lst"`
}

// StatusReference is used in credentials to reference a status list.
type StatusReference struct {
	// StatusListIndex is the index in the status list
	StatusListIndex int `json:"status_list_index"`
	// StatusListURI is the URI of the status list token
	StatusListURI string `json:"status_list_uri"`
}

// ToJSON serializes the status list token payload to JSON.
func (t *StatusListToken) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

// ParseStatusListToken parses a Status List Token payload from JSON.
func ParseStatusListToken(data []byte) (*StatusListToken, error) {
	var token StatusListToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse status list token: %w", err)
	}
	return &token, nil
}

// GetStatusList decodes the status list from the token.
func (t *StatusListToken) GetStatusList(size int) (*StatusList, error) {
	bps := BitsPerStatus(t.StatusList.Bits)
	return Decode(t.StatusList.List, size, bps)
}

// SetStatusList encodes and sets the status list in the token.
func (t *StatusListToken) SetStatusList(list *StatusList) error {
	encoded, err := list.Encode()
	if err != nil {
		return err
	}
	t.StatusList = StatusListClaim{
		Bits: int(list.bitsPerStatus),
		List: encoded,
	}
	return nil
}

// Sign creates a signed JWT for the status list token using the provided signer.
func (t *StatusListToken) Sign(s signer.Signer, opts *StatusListSignOptions) (string, error) {
	if s == nil {
		return "", fmt.Errorf("signer is required to sign status list token")
	}

	claims := jwt.MapClaims{
		"iss":         t.Issuer,
		"sub":         t.Subject,
		"iat":         t.IssuedAt,
		"status_list": t.StatusList,
	}
	if t.ExpiresAt != 0 {
		claims["exp"] = t.ExpiresAt
	}
	if t.TimeToLive != 0 {
		claims["ttl"] = t.TimeToLive
	}

	signingMethod := signer.NewSigningMethod(s)
	token := jwt.NewWithClaims(signingMethod, claims)

	if opts != nil {
		if opts.Type != "" {
			token.Header["typ"] = opts.Type
		}
		for k, v := range opts.ExtraHeaders {
			token.Header[k] = v
		}
	}

	signed, err := token.SignedString(nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign status list token: %w", err)
	}
	return signed, nil
}

// NewStatusListToken creates a new Status List Token with the given status list.
func NewStatusListToken(issuer, subject string, list *StatusList, issuedAt, expiresAt int64) (*StatusListToken, error) {
	token := &StatusListToken{
		Issuer:    issuer,
		Subject:   subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}

	if err := token.SetStatusList(list); err != nil {
		return nil, err
	}

	return token, nil
}
