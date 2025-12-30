package sdjwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Serialize converts an SDJWT to its compact serialization format.
// Format: <Issuer-signed JWT>~<D.1>~<D.2>~...~<D.N>~
func (s *SDJWT) Serialize() string {
	var builder strings.Builder

	// Start with the issuer-signed JWT
	builder.WriteString(s.IssuerSignedJWT)
	builder.WriteString(Separator)

	// Add each disclosure followed by a separator
	for _, d := range s.Disclosures {
		builder.WriteString(d.Encoded)
		builder.WriteString(Separator)
	}

	return builder.String()
}

// SerializeWithKB converts an SDJWTWithKB to its compact serialization format.
// Format: <Issuer-signed JWT>~<D.1>~<D.2>~...~<D.N>~<KB-JWT>
func (s *SDJWTWithKB) Serialize() string {
	var builder strings.Builder

	// Start with the issuer-signed JWT
	builder.WriteString(s.SDJWT.IssuerSignedJWT)
	builder.WriteString(Separator)

	// Add each disclosure followed by a separator
	for _, d := range s.SDJWT.Disclosures {
		builder.WriteString(d.Encoded)
		builder.WriteString(Separator)
	}

	// Add the Key Binding JWT (no trailing separator)
	builder.WriteString(s.KeyBindingJWT)

	return builder.String()
}

// Parse parses a compact-serialized SD-JWT string.
// It can parse both SD-JWT (ends with ~) and SD-JWT+KB (ends with KB-JWT).
// Returns an SDJWT and optionally a KB-JWT string if present.
func Parse(serialized string, hashAlgorithm string) (*SDJWT, string, error) {
	if serialized == "" {
		return nil, "", fmt.Errorf("empty SD-JWT string")
	}

	// Split by separator
	parts := strings.Split(serialized, Separator)
	if len(parts) < 2 {
		return nil, "", fmt.Errorf("invalid SD-JWT format: expected at least JWT and separator")
	}

	// First part is always the issuer-signed JWT
	issuerJWT := parts[0]
	if issuerJWT == "" {
		return nil, "", fmt.Errorf("invalid SD-JWT: missing issuer-signed JWT")
	}

	// Check if it's a valid JWT format (three parts separated by dots)
	jwtParts := strings.Split(issuerJWT, ".")
	if len(jwtParts) != 3 {
		return nil, "", fmt.Errorf("invalid issuer-signed JWT format")
	}

	// Determine if this is SD-JWT or SD-JWT+KB
	// SD-JWT ends with empty string (trailing ~)
	// SD-JWT+KB ends with KB-JWT (no trailing ~)
	lastPart := parts[len(parts)-1]
	var kbJWT string
	var disclosureParts []string

	if lastPart == "" {
		// SD-JWT (ends with ~)
		// Disclosures are parts[1] to parts[len(parts)-2]
		disclosureParts = parts[1 : len(parts)-1]
	} else {
		if !isJWT(lastPart) {
			return nil, "", fmt.Errorf("invalid SD-JWT format: expected KB-JWT or trailing separator")
		}
		kbJWT = lastPart
		// Disclosures are parts[1] to parts[len(parts)-2]
		disclosureParts = parts[1 : len(parts)-1]
	}

	hashAlgorithm, err := resolveHashAlgorithmFromJWT(issuerJWT, hashAlgorithm)
	if err != nil {
		return nil, "", err
	}

	// Parse disclosures
	var disclosures []Disclosure
	for _, dp := range disclosureParts {
		if dp == "" {
			return nil, "", fmt.Errorf("invalid SD-JWT format: empty disclosure")
		}
		d, err := ParseDisclosure(dp, hashAlgorithm)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse disclosure: %w", err)
		}
		disclosures = append(disclosures, *d)
	}

	sdjwt := &SDJWT{
		IssuerSignedJWT: issuerJWT,
		Disclosures:     disclosures,
		HashAlgorithm:   hashAlgorithm,
	}

	return sdjwt, kbJWT, nil
}

// ParseSDJWT parses a compact-serialized SD-JWT string (without KB-JWT).
func ParseSDJWT(serialized string, hashAlgorithm string) (*SDJWT, error) {
	sdjwt, kbJWT, err := Parse(serialized, hashAlgorithm)
	if err != nil {
		return nil, err
	}

	if kbJWT != "" {
		return nil, fmt.Errorf("expected SD-JWT but got SD-JWT+KB")
	}

	return sdjwt, nil
}

// ParseSDJWTWithKB parses a compact-serialized SD-JWT+KB string.
func ParseSDJWTWithKB(serialized string, hashAlgorithm string) (*SDJWTWithKB, error) {
	sdjwt, kbJWT, err := Parse(serialized, hashAlgorithm)
	if err != nil {
		return nil, err
	}

	if kbJWT == "" {
		return nil, fmt.Errorf("expected SD-JWT+KB but got SD-JWT without KB-JWT")
	}

	return &SDJWTWithKB{
		SDJWT:         *sdjwt,
		KeyBindingJWT: kbJWT,
	}, nil
}

// isJWT checks if a string looks like a JWT (three base64url parts separated by dots).
func isJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3
}

// GetSDJWTForHashing returns the SD-JWT string used for computing sd_hash.
// This is the SD-JWT without the KB-JWT, ending with a trailing separator.
func (s *SDJWT) GetSDJWTForHashing() string {
	return s.Serialize()
}

// FindDisclosureByDigest finds a disclosure by its digest value.
func (s *SDJWT) FindDisclosureByDigest(digest string) *Disclosure {
	for i := range s.Disclosures {
		if s.Disclosures[i].Digest == digest {
			return &s.Disclosures[i]
		}
	}
	return nil
}

// GetDisclosureDigests returns all disclosure digests as a set for quick lookup.
func (s *SDJWT) GetDisclosureDigests() map[string]bool {
	digests := make(map[string]bool)
	for _, d := range s.Disclosures {
		digests[d.Digest] = true
	}
	return digests
}

// SelectDisclosures creates a new SDJWT with only the selected disclosures.
// The selectedDigests map should contain the digests of disclosures to include.
func (s *SDJWT) SelectDisclosures(selectedDigests map[string]bool) *SDJWT {
	var selected []Disclosure
	for _, d := range s.Disclosures {
		if selectedDigests[d.Digest] {
			selected = append(selected, d)
		}
	}

	return &SDJWT{
		IssuerSignedJWT: s.IssuerSignedJWT,
		Disclosures:     selected,
		HashAlgorithm:   s.HashAlgorithm,
	}
}

// SDJWTJSONHeader represents the unprotected header parameters for SD-JWT JSON serialization.
type SDJWTJSONHeader struct {
	// Disclosures is an array of base64url-encoded disclosure strings.
	Disclosures []string `json:"disclosures,omitempty"`
	// KBJwt is the Key Binding JWT in compact form (optional).
	KBJwt string `json:"kb_jwt,omitempty"`
}

// FlattenJSON represents the Flattened JSON Serialization format for SD-JWT.
// This format separates the JWT components and includes disclosures in the header.
type FlattenJSON struct {
	// Protected is the base64url-encoded protected header
	Protected string `json:"protected"`
	// Header is the unprotected header containing disclosures and optional kb_jwt
	Header *SDJWTJSONHeader `json:"header,omitempty"`
	// Payload is the base64url-encoded JWT payload
	Payload string `json:"payload"`
	// Signature is the base64url-encoded signature
	Signature string `json:"signature"`
}

// GeneralJSON represents the General JSON Serialization format for SD-JWT.
// This format follows the JWS General JSON Serialization with SD-JWT extensions.
type GeneralJSON struct {
	// Payload is the base64url-encoded JWT payload
	Payload string `json:"payload"`
	// Signatures contains the signature information
	Signatures []GeneralJSONSignature `json:"signatures"`
}

// GeneralJSONSignature represents a signature in General JSON format.
type GeneralJSONSignature struct {
	// Protected is the base64url-encoded protected header
	Protected string `json:"protected"`
	// Header is the unprotected header containing disclosures and optional kb_jwt
	Header *SDJWTJSONHeader `json:"header,omitempty"`
	// Signature is the base64url-encoded signature
	Signature string `json:"signature"`
}

// ToFlattenJSON converts an SDJWT to Flattened JSON Serialization format.
func (s *SDJWT) ToFlattenJSON() (*FlattenJSON, error) {
	parts := strings.Split(s.IssuerSignedJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	header := buildJSONHeader(s.Disclosures, "")

	return &FlattenJSON{
		Protected: parts[0],
		Header:    header,
		Payload:   parts[1],
		Signature: parts[2],
	}, nil
}

// ToFlattenJSON converts an SDJWTWithKB to Flattened JSON Serialization format.
func (s *SDJWTWithKB) ToFlattenJSON() (*FlattenJSON, error) {
	flat, err := s.SDJWT.ToFlattenJSON()
	if err != nil {
		return nil, err
	}

	if s.KeyBindingJWT != "" {
		flat.Header = buildJSONHeader(s.SDJWT.Disclosures, s.KeyBindingJWT)
	}

	return flat, nil
}

// ToGeneralJSON converts an SDJWT to General JSON Serialization format.
func (s *SDJWT) ToGeneralJSON() (*GeneralJSON, error) {
	parts := strings.Split(s.IssuerSignedJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	header := buildJSONHeader(s.Disclosures, "")

	return &GeneralJSON{
		Payload: parts[1],
		Signatures: []GeneralJSONSignature{
			{
				Protected: parts[0],
				Header:    header,
				Signature: parts[2],
			},
		},
	}, nil
}

// ToGeneralJSON converts an SDJWTWithKB to General JSON Serialization format.
func (s *SDJWTWithKB) ToGeneralJSON() (*GeneralJSON, error) {
	general, err := s.SDJWT.ToGeneralJSON()
	if err != nil {
		return nil, err
	}

	if s.KeyBindingJWT != "" {
		general.Signatures[0].Header = buildJSONHeader(s.SDJWT.Disclosures, s.KeyBindingJWT)
	}

	return general, nil
}

// FromFlattenJSON creates an SDJWT from Flattened JSON Serialization format.
func FromFlattenJSON(flat *FlattenJSON, hashAlgorithm string) (*SDJWT, string, error) {
	// Reconstruct JWT
	jwt := flat.Protected + "." + flat.Payload + "." + flat.Signature

	disclosures, kbJWT, err := disclosuresFromJSONHeader(flat.Header)
	if err != nil {
		return nil, "", err
	}

	hashAlgorithm, err = resolveHashAlgorithmFromPayload(flat.Payload, hashAlgorithm)
	if err != nil {
		return nil, "", err
	}

	// Parse disclosures
	var parsedDisclosures []Disclosure
	for _, encoded := range disclosures {
		d, err := ParseDisclosure(encoded, hashAlgorithm)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse disclosure: %w", err)
		}
		parsedDisclosures = append(parsedDisclosures, *d)
	}

	sdjwt := &SDJWT{
		IssuerSignedJWT: jwt,
		Disclosures:     parsedDisclosures,
		HashAlgorithm:   hashAlgorithm,
	}

	return sdjwt, kbJWT, nil
}

// FromGeneralJSON creates an SDJWT from General JSON Serialization format.
func FromGeneralJSON(general *GeneralJSON, hashAlgorithm string) (*SDJWT, string, error) {
	if len(general.Signatures) == 0 {
		return nil, "", fmt.Errorf("no signatures in general JSON")
	}

	// Use first signature (SD-JWT only has one issuer signature)
	sig := general.Signatures[0]
	jwt := sig.Protected + "." + general.Payload + "." + sig.Signature

	disclosures, kbJWT, err := disclosuresFromJSONHeader(sig.Header)
	if err != nil {
		return nil, "", err
	}

	for i := 1; i < len(general.Signatures); i++ {
		if general.Signatures[i].Header != nil {
			if len(general.Signatures[i].Header.Disclosures) > 0 || general.Signatures[i].Header.KBJwt != "" {
				return nil, "", fmt.Errorf("disclosures and kb_jwt must only appear in the first unprotected header")
			}
		}
	}

	hashAlgorithm, err = resolveHashAlgorithmFromPayload(general.Payload, hashAlgorithm)
	if err != nil {
		return nil, "", err
	}

	// Parse disclosures
	var parsedDisclosures []Disclosure
	for _, encoded := range disclosures {
		d, err := ParseDisclosure(encoded, hashAlgorithm)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse disclosure: %w", err)
		}
		parsedDisclosures = append(parsedDisclosures, *d)
	}

	sdjwt := &SDJWT{
		IssuerSignedJWT: jwt,
		Disclosures:     parsedDisclosures,
		HashAlgorithm:   hashAlgorithm,
	}

	return sdjwt, kbJWT, nil
}

// SerializeFlattenJSON serializes an SDJWT to a JSON string in Flattened format.
func (s *SDJWT) SerializeFlattenJSON() (string, error) {
	flat, err := s.ToFlattenJSON()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(flat)
	if err != nil {
		return "", fmt.Errorf("failed to marshal FlattenJSON: %w", err)
	}
	return string(data), nil
}

// SerializeFlattenJSON serializes an SDJWTWithKB to a JSON string in Flattened format.
func (s *SDJWTWithKB) SerializeFlattenJSON() (string, error) {
	flat, err := s.ToFlattenJSON()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(flat)
	if err != nil {
		return "", fmt.Errorf("failed to marshal FlattenJSON: %w", err)
	}
	return string(data), nil
}

// SerializeGeneralJSON serializes an SDJWT to a JSON string in General format.
func (s *SDJWT) SerializeGeneralJSON() (string, error) {
	general, err := s.ToGeneralJSON()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(general)
	if err != nil {
		return "", fmt.Errorf("failed to marshal GeneralJSON: %w", err)
	}
	return string(data), nil
}

// SerializeGeneralJSON serializes an SDJWTWithKB to a JSON string in General format.
func (s *SDJWTWithKB) SerializeGeneralJSON() (string, error) {
	general, err := s.ToGeneralJSON()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(general)
	if err != nil {
		return "", fmt.Errorf("failed to marshal GeneralJSON: %w", err)
	}
	return string(data), nil
}

// ParseFlattenJSON parses a Flattened JSON serialization string into an SDJWT.
func ParseFlattenJSON(jsonStr string, hashAlgorithm string) (*SDJWT, string, error) {
	var flat FlattenJSON
	if err := json.Unmarshal([]byte(jsonStr), &flat); err != nil {
		return nil, "", fmt.Errorf("failed to parse FlattenJSON: %w", err)
	}
	return FromFlattenJSON(&flat, hashAlgorithm)
}

// ParseGeneralJSON parses a General JSON serialization string into an SDJWT.
func ParseGeneralJSON(jsonStr string, hashAlgorithm string) (*SDJWT, string, error) {
	var general GeneralJSON
	if err := json.Unmarshal([]byte(jsonStr), &general); err != nil {
		return nil, "", fmt.Errorf("failed to parse GeneralJSON: %w", err)
	}
	return FromGeneralJSON(&general, hashAlgorithm)
}
