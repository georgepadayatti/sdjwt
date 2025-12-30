// Package sdjwt provides tests implementing RFC 9901 examples to verify conformance.
// These tests cover Section 5, Section 6, and Appendix A examples from the specification.
package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// TestRFC9901Section5_DisclosureFormat tests the disclosure format from Section 5.
// Disclosure format for object properties: ["salt", "claim_name", "claim_value"]
// Disclosure format for array elements: ["salt", "value"]
func TestRFC9901Section5_DisclosureFormat(t *testing.T) {
	t.Run("object property disclosure format", func(t *testing.T) {
		// Example from Section 5: given_name disclosure
		// Contents: ["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]
		salt := "2GLC42sKQveCfGfryNRN9w"
		claimName := "given_name"
		claimValue := "John"

		d, err := NewDisclosureWithSalt(salt, claimName, claimValue, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		// Verify the structure
		if d.Salt != salt {
			t.Errorf("Salt = %q, want %q", d.Salt, salt)
		}
		if d.ClaimName != claimName {
			t.Errorf("ClaimName = %q, want %q", d.ClaimName, claimName)
		}
		if d.ClaimValue != claimValue {
			t.Errorf("ClaimValue = %v, want %v", d.ClaimValue, claimValue)
		}

		// Verify it's not an array element
		if d.IsArrayElement() {
			t.Error("Object property disclosure should not be an array element")
		}

		// Verify the encoded disclosure decodes to [salt, claim_name, claim_value]
		decoded, err := Base64URLDecode(d.Encoded)
		if err != nil {
			t.Fatalf("Failed to decode disclosure: %v", err)
		}

		var arr []any
		if err := json.Unmarshal(decoded, &arr); err != nil {
			t.Fatalf("Failed to parse disclosure JSON: %v", err)
		}

		if len(arr) != 3 {
			t.Fatalf("Disclosure array length = %d, want 3", len(arr))
		}

		if arr[0] != salt {
			t.Errorf("arr[0] (salt) = %v, want %v", arr[0], salt)
		}
		if arr[1] != claimName {
			t.Errorf("arr[1] (claim_name) = %v, want %v", arr[1], claimName)
		}
		if arr[2] != claimValue {
			t.Errorf("arr[2] (claim_value) = %v, want %v", arr[2], claimValue)
		}
	})

	t.Run("array element disclosure format", func(t *testing.T) {
		// Example from Section 5: nationalities array element disclosure
		// Contents: ["lklxF5jMYlGTPUovMNIvCA", "US"]
		salt := "lklxF5jMYlGTPUovMNIvCA"
		value := "US"

		d, err := NewArrayElementDisclosureWithSalt(salt, value, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create array element disclosure: %v", err)
		}

		// Verify the structure
		if d.Salt != salt {
			t.Errorf("Salt = %q, want %q", d.Salt, salt)
		}
		if d.ClaimName != "" {
			t.Errorf("ClaimName = %q, want empty string for array element", d.ClaimName)
		}
		if d.ClaimValue != value {
			t.Errorf("ClaimValue = %v, want %v", d.ClaimValue, value)
		}

		// Verify it is an array element
		if !d.IsArrayElement() {
			t.Error("Array element disclosure should be an array element")
		}

		// Verify the encoded disclosure decodes to [salt, value]
		decoded, err := Base64URLDecode(d.Encoded)
		if err != nil {
			t.Fatalf("Failed to decode disclosure: %v", err)
		}

		var arr []any
		if err := json.Unmarshal(decoded, &arr); err != nil {
			t.Fatalf("Failed to parse disclosure JSON: %v", err)
		}

		if len(arr) != 2 {
			t.Fatalf("Array element disclosure length = %d, want 2", len(arr))
		}

		if arr[0] != salt {
			t.Errorf("arr[0] (salt) = %v, want %v", arr[0], salt)
		}
		if arr[1] != value {
			t.Errorf("arr[1] (value) = %v, want %v", arr[1], value)
		}
	})
}

// TestRFC9901Section5_HashDigestCalculation tests the hash digest calculation from Section 5.
// The RFC provides exact Base64URL-encoded disclosure strings with specific JSON formatting.
// Our implementation uses compact JSON (no spaces), so we test parsing the RFC's exact strings.
func TestRFC9901Section5_HashDigestCalculation(t *testing.T) {
	// Test cases from Section 5 of RFC 9901
	// These are the EXACT encoded disclosures from the RFC specification
	testCases := []struct {
		name           string
		encoded        string // Exact Base64URL-encoded disclosure from RFC
		expectedDigest string // From the RFC examples
		salt           string
		claimName      string
		claimValue     any
	}{
		{
			name:           "given_name disclosure",
			encoded:        "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			expectedDigest: "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
			salt:           "2GLC42sKQveCfGfryNRN9w",
			claimName:      "given_name",
			claimValue:     "John",
		},
		{
			name:           "family_name disclosure",
			encoded:        "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
			expectedDigest: "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
			salt:           "eluV5Og3gSNII8EYnsxA_A",
			claimName:      "family_name",
			claimValue:     "Doe",
		},
		{
			name:           "email disclosure",
			encoded:        "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
			expectedDigest: "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
			salt:           "6Ij7tM-a5iVPGboS5tmvVA",
			claimName:      "email",
			claimValue:     "johndoe@example.com",
		},
		{
			name:           "phone_number disclosure",
			encoded:        "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ",
			expectedDigest: "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
			salt:           "eI8ZWm9QnKPpNPeNenHdhQ",
			claimName:      "phone_number",
			claimValue:     "+1-202-555-0101",
		},
		{
			name:           "phone_number_verified disclosure",
			encoded:        "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd",
			expectedDigest: "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM",
			salt:           "Qg_O64zqAxe412a108iroA",
			claimName:      "phone_number_verified",
			claimValue:     true,
		},
		{
			name:           "birthdate disclosure",
			encoded:        "WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0",
			expectedDigest: "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM",
			salt:           "Pc33JM2LchcU_lHggv_ufQ",
			claimName:      "birthdate",
			claimValue:     "1940-01-01",
		},
		{
			name:           "updated_at disclosure",
			encoded:        "WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ",
			expectedDigest: "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI",
			salt:           "G02NSrQfjFXQ7Io09syajA",
			claimName:      "updated_at",
			claimValue:     float64(1570000000), // JSON numbers are float64
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the RFC's exact encoded disclosure
			parsed, err := ParseDisclosure(tc.encoded, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to parse RFC disclosure: %v", err)
			}

			// Verify the parsed content matches expected values
			if parsed.Salt != tc.salt {
				t.Errorf("Salt = %q, want %q", parsed.Salt, tc.salt)
			}
			if parsed.ClaimName != tc.claimName {
				t.Errorf("ClaimName = %q, want %q", parsed.ClaimName, tc.claimName)
			}

			// Verify the digest matches the RFC expected value
			if parsed.Digest != tc.expectedDigest {
				t.Errorf("Digest = %q, want %q", parsed.Digest, tc.expectedDigest)
			}
		})
	}
}

// TestRFC9901Section5_ArrayElementDigest tests array element digest calculation.
// Uses the RFC's exact encoded disclosure strings for nationalities array.
func TestRFC9901Section5_ArrayElementDigest(t *testing.T) {
	testCases := []struct {
		name           string
		encoded        string // Exact Base64URL-encoded disclosure from RFC
		salt           string
		value          string
		expectedDigest string
	}{
		{
			name:           "US nationality",
			encoded:        "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0",
			salt:           "lklxF5jMYlGTPUovMNIvCA",
			value:          "US",
			expectedDigest: "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo",
		},
		{
			name:           "DE nationality",
			encoded:        "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0",
			salt:           "nPuoQnkRFq3BIeAm7AnXFA",
			value:          "DE",
			expectedDigest: "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the RFC's exact encoded disclosure
			parsed, err := ParseDisclosure(tc.encoded, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to parse RFC disclosure: %v", err)
			}

			// Verify it's an array element (2 elements, no claim name)
			if !parsed.IsArrayElement() {
				t.Error("Should be an array element disclosure")
			}

			// Verify the parsed content
			if parsed.Salt != tc.salt {
				t.Errorf("Salt = %q, want %q", parsed.Salt, tc.salt)
			}
			if parsed.ClaimValue != tc.value {
				t.Errorf("Value = %v, want %v", parsed.ClaimValue, tc.value)
			}

			// Verify the digest matches the RFC expected value
			if parsed.Digest != tc.expectedDigest {
				t.Errorf("Digest = %q, want %q", parsed.Digest, tc.expectedDigest)
			}
		})
	}
}

// TestRFC9901Section5_AddressDisclosure tests the flat address disclosure from Section 5.
// The RFC shows the address as a single disclosure containing a nested object.
func TestRFC9901Section5_AddressDisclosure(t *testing.T) {
	// The RFC provides this exact encoded address disclosure from Section 5:
	// ["AJx-095VPrpTtN4QMOqROA", "address", {"street_address": "123 Main St", ...}]
	// The exact encoding depends on JSON key ordering, which may vary.
	// We test that our implementation can handle nested objects in disclosures.

	t.Run("nested object in disclosure", func(t *testing.T) {
		salt := "AJx-095VPrpTtN4QMOqROA"
		claimName := "address"
		claimValue := map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		}

		d, err := NewDisclosureWithSalt(salt, claimName, claimValue, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		// Verify the structure is preserved
		if d.Salt != salt {
			t.Errorf("Salt = %q, want %q", d.Salt, salt)
		}
		if d.ClaimName != claimName {
			t.Errorf("ClaimName = %q, want %q", d.ClaimName, claimName)
		}

		// Parse and verify round-trip
		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		parsedMap, ok := parsed.ClaimValue.(map[string]any)
		if !ok {
			t.Fatal("ClaimValue should be a map")
		}

		if parsedMap["street_address"] != "123 Main St" {
			t.Errorf("street_address = %v, want %q", parsedMap["street_address"], "123 Main St")
		}
		if parsedMap["locality"] != "Anytown" {
			t.Errorf("locality = %v, want %q", parsedMap["locality"], "Anytown")
		}

		// Verify digest is computed and valid
		if d.Digest == "" {
			t.Error("Digest should not be empty")
		}
		if len(d.Digest) != 43 { // SHA-256 produces 43 base64url chars
			t.Errorf("Digest length = %d, want 43", len(d.Digest))
		}
	})
}

// TestRFC9901Section5_SDArrayContent tests the _sd array structure from Section 5.
// This test verifies the structure of the _sd array using the RFC's exact encoded disclosures.
func TestRFC9901Section5_SDArrayContent(t *testing.T) {
	// The RFC provides exact encoded disclosures. When parsed, they produce specific digests.
	// The _sd array in the JWT payload should contain these digests.
	rfcDisclosures := []struct {
		encoded        string
		expectedDigest string
		claimName      string
	}{
		{"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd", "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4", "given_name"},
		{"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd", "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo", "family_name"},
		{"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ", "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE", "email"},
		{"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ", "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI", "phone_number"},
		{"WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd", "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM", "phone_number_verified"},
		{"WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0", "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM", "birthdate"},
		{"WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ", "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI", "updated_at"},
	}

	digestToClaimMap := make(map[string]string)
	var digests []string

	for _, disc := range rfcDisclosures {
		parsed, err := ParseDisclosure(disc.encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse RFC disclosure for %s: %v", disc.claimName, err)
		}

		// Verify the digest matches expected
		if parsed.Digest != disc.expectedDigest {
			t.Errorf("Digest for %s = %q, want %q", disc.claimName, parsed.Digest, disc.expectedDigest)
		}

		digestToClaimMap[parsed.Digest] = disc.claimName
		digests = append(digests, parsed.Digest)
	}

	// Verify we have all expected claims
	expectedClaims := []string{"given_name", "family_name", "email", "phone_number", "phone_number_verified", "birthdate", "updated_at"}
	for _, claim := range expectedClaims {
		found := false
		for _, c := range digestToClaimMap {
			if c == claim {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing claim %s in digest map", claim)
		}
	}
}

// TestRFC9901Section5_ArrayElementPlaceholder tests the {"...": "digest"} format.
func TestRFC9901Section5_ArrayElementPlaceholder(t *testing.T) {
	// From Section 5: nationalities array contains placeholders
	// {"...": "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"}
	// {"...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"}

	// Parse the RFC's exact encoded array element disclosures
	usDisclosure, err := ParseDisclosure("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0", HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to parse US disclosure: %v", err)
	}

	deDisclosure, err := ParseDisclosure("WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0", HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to parse DE disclosure: %v", err)
	}

	// Verify the placeholder format using the expected digests
	expectedUSDigest := "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"
	expectedDEDigest := "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"

	usPlaceholder := map[string]string{SDListKey: usDisclosure.Digest}
	dePlaceholder := map[string]string{SDListKey: deDisclosure.Digest}

	if usPlaceholder[SDListKey] != expectedUSDigest {
		t.Errorf("US placeholder digest = %q, want %q", usPlaceholder[SDListKey], expectedUSDigest)
	}

	if dePlaceholder[SDListKey] != expectedDEDigest {
		t.Errorf("DE placeholder digest = %q, want %q", dePlaceholder[SDListKey], expectedDEDigest)
	}

	// Verify the SDListKey constant is correct
	if SDListKey != "..." {
		t.Errorf("SDListKey = %q, want %q", SDListKey, "...")
	}
}

// TestRFC9901Section6_1_FlatStructure tests the flat SD-JWT structure from Section 6.1.
// In flat structure, the entire nested object (address) is a single disclosure.
func TestRFC9901Section6_1_FlatStructure(t *testing.T) {
	// Section 6.1: Address as a single disclosure (flat structure)
	// The entire address object becomes one disclosure.
	salt := "2GLC42sKQveCfGfryNRN9w"
	claimName := "address"
	claimValue := map[string]any{
		"street_address": "Schulstr. 12",
		"locality":       "Schulpforta",
		"region":         "Sachsen-Anhalt",
		"country":        "DE",
	}

	d, err := NewDisclosureWithSalt(salt, claimName, claimValue, HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create disclosure: %v", err)
	}

	// Verify it's not an array element
	if d.IsArrayElement() {
		t.Error("Flat address disclosure should not be an array element")
	}

	// Verify the structure is preserved through round-trip
	parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to parse disclosure: %v", err)
	}

	valueMap, ok := parsed.ClaimValue.(map[string]any)
	if !ok {
		t.Fatal("ClaimValue should be a map")
	}

	if valueMap["street_address"] != "Schulstr. 12" {
		t.Errorf("street_address = %v, want Schulstr. 12", valueMap["street_address"])
	}
	if valueMap["locality"] != "Schulpforta" {
		t.Errorf("locality = %v, want Schulpforta", valueMap["locality"])
	}
	if valueMap["region"] != "Sachsen-Anhalt" {
		t.Errorf("region = %v, want Sachsen-Anhalt", valueMap["region"])
	}
	if valueMap["country"] != "DE" {
		t.Errorf("country = %v, want DE", valueMap["country"])
	}

	// Verify digest is computed
	if d.Digest == "" {
		t.Error("Digest should not be empty")
	}
	if len(d.Digest) != 43 { // SHA-256 produces 43 base64url chars
		t.Errorf("Digest length = %d, want 43", len(d.Digest))
	}
}

// TestRFC9901Section6_2_StructuredDisclosures tests the structured SD-JWT from Section 6.2.
// In structured SD-JWT, each sub-claim of the address is individually disclosable.
func TestRFC9901Section6_2_StructuredDisclosures(t *testing.T) {
	// Section 6.2: Address sub-claims individually disclosable
	// Each sub-claim (street_address, locality, region, country) becomes its own disclosure.
	testCases := []struct {
		name       string
		salt       string
		claimName  string
		claimValue string
	}{
		{
			name:       "street_address",
			salt:       "2GLC42sKQveCfGfryNRN9w",
			claimName:  "street_address",
			claimValue: "Schulstr. 12",
		},
		{
			name:       "locality",
			salt:       "eluV5Og3gSNII8EYnsxA_A",
			claimName:  "locality",
			claimValue: "Schulpforta",
		},
		{
			name:       "region",
			salt:       "6Ij7tM-a5iVPGboS5tmvVA",
			claimName:  "region",
			claimValue: "Sachsen-Anhalt",
		},
		{
			name:       "country",
			salt:       "eI8ZWm9QnKPpNPeNenHdhQ",
			claimName:  "country",
			claimValue: "DE",
		},
	}

	var digests []string

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDisclosureWithSalt(tc.salt, tc.claimName, tc.claimValue, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to create disclosure: %v", err)
			}

			// Verify structure
			if d.Salt != tc.salt {
				t.Errorf("Salt = %q, want %q", d.Salt, tc.salt)
			}
			if d.ClaimName != tc.claimName {
				t.Errorf("ClaimName = %q, want %q", d.ClaimName, tc.claimName)
			}
			if d.ClaimValue != tc.claimValue {
				t.Errorf("ClaimValue = %v, want %v", d.ClaimValue, tc.claimValue)
			}

			// Verify digest is computed and valid
			if d.Digest == "" {
				t.Error("Digest should not be empty")
			}
			if len(d.Digest) != 43 {
				t.Errorf("Digest length = %d, want 43", len(d.Digest))
			}

			// Verify round-trip
			parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to parse disclosure: %v", err)
			}
			if parsed.ClaimValue != tc.claimValue {
				t.Errorf("Parsed ClaimValue = %v, want %v", parsed.ClaimValue, tc.claimValue)
			}

			digests = append(digests, d.Digest)
		})
	}

	// In structured SD-JWT, the address object in the payload would contain:
	// "address": { "_sd": [...digests...] }
	t.Run("verify_sd_array_structure", func(t *testing.T) {
		if len(digests) != 4 {
			t.Errorf("Expected 4 digests for address sub-claims, got %d", len(digests))
		}
	})
}

// TestRFC9901Section6_3_RecursiveDisclosures tests recursive disclosures from Section 6.3.
// In recursive SD-JWT, both the parent object (address) AND its sub-claims are selectively disclosable.
func TestRFC9901Section6_3_RecursiveDisclosures(t *testing.T) {
	// Section 6.3: Both the address claim and its sub-claims are SD
	// This creates a two-level selective disclosure structure.

	// First, create sub-claim disclosures (same as Section 6.2)
	streetD, err := NewDisclosureWithSalt("2GLC42sKQveCfGfryNRN9w", "street_address", "Schulstr. 12", HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create street_address disclosure: %v", err)
	}
	localityD, err := NewDisclosureWithSalt("eluV5Og3gSNII8EYnsxA_A", "locality", "Schulpforta", HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create locality disclosure: %v", err)
	}
	regionD, err := NewDisclosureWithSalt("6Ij7tM-a5iVPGboS5tmvVA", "region", "Sachsen-Anhalt", HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create region disclosure: %v", err)
	}
	countryD, err := NewDisclosureWithSalt("eI8ZWm9QnKPpNPeNenHdhQ", "country", "DE", HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create country disclosure: %v", err)
	}

	// The address disclosure contains an _sd array with the sub-claim digests
	// This represents the address object with its sub-claims hidden
	addressValue := map[string]any{
		"_sd": []string{
			localityD.Digest,
			streetD.Digest,
			regionD.Digest,
			countryD.Digest,
		},
	}

	// Create the parent address disclosure
	addressD, err := NewDisclosureWithSalt("Qg_O64zqAxe412a108iroA", "address", addressValue, HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create address disclosure: %v", err)
	}

	// Verify the address claim value contains _sd array
	addressMap, ok := addressD.ClaimValue.(map[string]any)
	if !ok {
		t.Fatal("Address ClaimValue should be a map")
	}

	sdArr, ok := addressMap["_sd"].([]string)
	if !ok {
		t.Fatal("Address should contain _sd array")
	}

	if len(sdArr) != 4 {
		t.Errorf("_sd array length = %d, want 4", len(sdArr))
	}

	// Verify all sub-claim digests are present in the _sd array
	subClaimDigests := []string{streetD.Digest, localityD.Digest, regionD.Digest, countryD.Digest}
	for _, subDigest := range subClaimDigests {
		found := false
		for _, d := range sdArr {
			if d == subDigest {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Sub-claim digest %s not found in _sd array", subDigest)
		}
	}

	// Verify round-trip of the parent address disclosure
	parsed, err := ParseDisclosure(addressD.Encoded, HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to parse address disclosure: %v", err)
	}

	parsedMap, ok := parsed.ClaimValue.(map[string]any)
	if !ok {
		t.Fatal("Parsed ClaimValue should be a map")
	}

	parsedSD, ok := parsedMap["_sd"].([]any)
	if !ok {
		t.Fatal("Parsed address should contain _sd array")
	}

	if len(parsedSD) != 4 {
		t.Errorf("Parsed _sd array length = %d, want 4", len(parsedSD))
	}
}

// TestRFC9901_SDAlgClaim tests the _sd_alg claim handling.
func TestRFC9901_SDAlgClaim(t *testing.T) {
	// _sd_alg should only be included when there are disclosures
	t.Run("sha-256 is default", func(t *testing.T) {
		if DefaultHashAlgorithm != "sha-256" {
			t.Errorf("DefaultHashAlgorithm = %q, want %q", DefaultHashAlgorithm, "sha-256")
		}
	})

	t.Run("supported algorithms", func(t *testing.T) {
		algorithms := []string{HashAlgSHA256, HashAlgSHA384, HashAlgSHA512}
		for _, alg := range algorithms {
			if !IsSupportedHashAlgorithm(alg) {
				t.Errorf("Algorithm %s should be supported", alg)
			}
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		if IsSupportedHashAlgorithm("sha-1") {
			t.Error("SHA-1 should not be supported")
		}
	})
}

// TestRFC9901_ReservedClaimNames tests that _sd and ... are reserved.
func TestRFC9901_ReservedClaimNames(t *testing.T) {
	// Per RFC 9901 Section 7.1, _sd and ... are reserved claim names
	t.Run("_sd is reserved", func(t *testing.T) {
		err := ValidateDisclosureClaimName("_sd")
		if err == nil {
			t.Error("Expected error for reserved claim name _sd")
		}
	})

	t.Run("... is reserved", func(t *testing.T) {
		err := ValidateDisclosureClaimName("...")
		if err == nil {
			t.Error("Expected error for reserved claim name ...")
		}
	})

	t.Run("regular names are valid", func(t *testing.T) {
		validNames := []string{"given_name", "family_name", "email", "address", "nationalities"}
		for _, name := range validNames {
			err := ValidateDisclosureClaimName(name)
			if err != nil {
				t.Errorf("Name %q should be valid, got error: %v", name, err)
			}
		}
	})
}

// TestRFC9901_SaltGeneration tests salt generation requirements.
func TestRFC9901_SaltGeneration(t *testing.T) {
	// RFC 9901 requires at least 128 bits of entropy for salts
	t.Run("salt length is 128 bits", func(t *testing.T) {
		if SaltLength != 16 { // 16 bytes = 128 bits
			t.Errorf("SaltLength = %d, want 16 (128 bits)", SaltLength)
		}
	})

	t.Run("salts are unique", func(t *testing.T) {
		salts := make(map[string]bool)
		for i := 0; i < 100; i++ {
			salt, err := GenerateSalt()
			if err != nil {
				t.Fatalf("Failed to generate salt: %v", err)
			}
			if salts[salt] {
				t.Error("Generated duplicate salt")
			}
			salts[salt] = true
		}
	})

	t.Run("salt is base64url encoded", func(t *testing.T) {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("Failed to generate salt: %v", err)
		}

		decoded, err := Base64URLDecode(salt)
		if err != nil {
			t.Errorf("Salt is not valid base64url: %v", err)
		}

		if len(decoded) != SaltLength {
			t.Errorf("Decoded salt length = %d, want %d", len(decoded), SaltLength)
		}
	})
}

// TestRFC9901_DecoyDigests tests decoy digest generation.
func TestRFC9901_DecoyDigests(t *testing.T) {
	// Decoy digests are used to hide the number of actual claims
	t.Run("decoy digests are unique", func(t *testing.T) {
		decoys := make(map[string]bool)
		for i := 0; i < 100; i++ {
			decoy, err := GenerateDecoyDigest(HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to generate decoy: %v", err)
			}
			if decoys[decoy] {
				t.Error("Generated duplicate decoy digest")
			}
			decoys[decoy] = true
		}
	})

	t.Run("decoy has correct length for sha-256", func(t *testing.T) {
		decoy, err := GenerateDecoyDigest(HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to generate decoy: %v", err)
		}
		// SHA-256 produces 32 bytes = 43 base64url chars (without padding)
		if len(decoy) != 43 {
			t.Errorf("Decoy length = %d, want 43", len(decoy))
		}
	})
}

// TestRFC9901_KeyBindingJWTType tests the KB-JWT type header.
func TestRFC9901_KeyBindingJWTType(t *testing.T) {
	// KB-JWT must have typ "kb+jwt"
	if KBJWTType != "kb+jwt" {
		t.Errorf("KBJWTType = %q, want %q", KBJWTType, "kb+jwt")
	}
}

// TestRFC9901_Separator tests the separator character.
func TestRFC9901_Separator(t *testing.T) {
	// SD-JWT uses tilde (~) as separator
	if Separator != "~" {
		t.Errorf("Separator = %q, want %q", Separator, "~")
	}
}

// TestRFC9901_SerializationFormat tests the compact serialization format.
func TestRFC9901_SerializationFormat(t *testing.T) {
	// Generate test key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("SD-JWT format ends with ~", func(t *testing.T) {
		// Create a simple SDJWT
		sdjwt := &SDJWT{
			IssuerSignedJWT: "eyJ.eyJ.sig",
			Disclosures:     []Disclosure{},
			HashAlgorithm:   HashAlgSHA256,
		}

		serialized := sdjwt.Serialize()
		if serialized[len(serialized)-1] != '~' {
			t.Error("SD-JWT should end with ~")
		}
	})

	t.Run("SD-JWT+KB format does not end with ~", func(t *testing.T) {
		// Format: <JWT>~<D1>~...<DN>~<KB-JWT>
		sdjwtKB := &SDJWTWithKB{
			SDJWT: SDJWT{
				IssuerSignedJWT: "eyJ.eyJ.sig",
				Disclosures:     []Disclosure{},
				HashAlgorithm:   HashAlgSHA256,
			},
			KeyBindingJWT: "eyJ.eyJ.kbsig",
		}

		serialized := sdjwtKB.Serialize()
		if serialized[len(serialized)-1] == '~' {
			t.Error("SD-JWT+KB should not end with ~")
		}
	})

	_ = key // Unused but kept for potential future tests
}

// TestRFC9901_ParseDisclosure tests parsing of disclosures.
func TestRFC9901_ParseDisclosure(t *testing.T) {
	t.Run("parse object property disclosure", func(t *testing.T) {
		// Create a disclosure
		original, _ := NewDisclosureWithSalt("test_salt", "claim", "value", HashAlgSHA256)

		// Parse it back
		parsed, err := ParseDisclosure(original.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		if parsed.Salt != original.Salt {
			t.Errorf("Salt = %q, want %q", parsed.Salt, original.Salt)
		}
		if parsed.ClaimName != original.ClaimName {
			t.Errorf("ClaimName = %q, want %q", parsed.ClaimName, original.ClaimName)
		}
		if parsed.ClaimValue != original.ClaimValue {
			t.Errorf("ClaimValue = %v, want %v", parsed.ClaimValue, original.ClaimValue)
		}
		if parsed.Digest != original.Digest {
			t.Errorf("Digest = %q, want %q", parsed.Digest, original.Digest)
		}
	})

	t.Run("parse array element disclosure", func(t *testing.T) {
		original, _ := NewArrayElementDisclosureWithSalt("test_salt", "element", HashAlgSHA256)

		parsed, err := ParseDisclosure(original.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		if parsed.Salt != original.Salt {
			t.Errorf("Salt = %q, want %q", parsed.Salt, original.Salt)
		}
		if !parsed.IsArrayElement() {
			t.Error("Should be array element")
		}
		if parsed.ClaimValue != original.ClaimValue {
			t.Errorf("ClaimValue = %v, want %v", parsed.ClaimValue, original.ClaimValue)
		}
	})

	t.Run("invalid disclosure length", func(t *testing.T) {
		// Create an invalid disclosure with wrong number of elements
		invalid := Base64URLEncode([]byte(`["salt", "too", "many", "elements"]`))
		_, err := ParseDisclosure(invalid, HashAlgSHA256)
		if err == nil {
			t.Error("Expected error for invalid disclosure length")
		}
	})
}

// TestRFC9901_HashAlgorithms tests all supported hash algorithms.
func TestRFC9901_HashAlgorithms(t *testing.T) {
	testCases := []struct {
		alg            string
		expectedLength int // Base64url encoded length without padding
	}{
		{HashAlgSHA256, 43},
		{HashAlgSHA384, 64},
		{HashAlgSHA512, 86},
	}

	for _, tc := range testCases {
		t.Run(tc.alg, func(t *testing.T) {
			d, err := NewDisclosure("test", "value", tc.alg)
			if err != nil {
				t.Fatalf("Failed to create disclosure with %s: %v", tc.alg, err)
			}

			if len(d.Digest) != tc.expectedLength {
				t.Errorf("Digest length for %s = %d, want %d", tc.alg, len(d.Digest), tc.expectedLength)
			}
		})
	}
}

// TestRFC9901_ComplexNestedValue tests disclosures with complex nested values.
func TestRFC9901_ComplexNestedValue(t *testing.T) {
	// Test from Appendix A.2 - verified_claims structure
	complexValue := map[string]any{
		"verification": map[string]any{
			"trust_framework": "de_aml",
			"evidence": []any{
				map[string]any{
					"type":   "document",
					"method": "pipp",
				},
			},
		},
		"claims": map[string]any{
			"given_name":  "Max",
			"family_name": "Müller",
		},
	}

	d, err := NewDisclosureWithSalt("test_salt", "verified_claims", complexValue, HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create disclosure with complex value: %v", err)
	}

	if d.ClaimName != "verified_claims" {
		t.Errorf("ClaimName = %q, want %q", d.ClaimName, "verified_claims")
	}

	// Parse and verify the value is preserved
	parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
	if err != nil {
		t.Fatalf("Failed to parse disclosure: %v", err)
	}

	// The parsed value should be a map
	parsedMap, ok := parsed.ClaimValue.(map[string]any)
	if !ok {
		t.Fatal("Parsed ClaimValue should be a map")
	}

	// Check nested structure
	verification, ok := parsedMap["verification"].(map[string]any)
	if !ok {
		t.Fatal("verification should be a map")
	}

	if verification["trust_framework"] != "de_aml" {
		t.Errorf("trust_framework = %v, want de_aml", verification["trust_framework"])
	}
}

// TestRFC9901_UnicodeValues tests handling of Unicode values (from Appendix A.1).
func TestRFC9901_UnicodeValues(t *testing.T) {
	// Appendix A.1 uses Japanese characters
	// given_name: 太郎 (Taro)
	// family_name: 山田 (Yamada)

	t.Run("japanese given_name", func(t *testing.T) {
		// The RFC uses Unicode escapes: \u592a\u90ce
		salt := "eluV5Og3gSNII8EYnsxA_A"
		value := "太郎" // or "\u592a\u90ce"

		d, err := NewDisclosureWithSalt(salt, "given_name", value, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		// Parse back and verify
		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		if parsed.ClaimValue != value {
			t.Errorf("ClaimValue = %v, want %v", parsed.ClaimValue, value)
		}
	})

	t.Run("japanese address", func(t *testing.T) {
		// Street address from A.1: 東京都港区芝公園４丁目２−８
		salt := "AJx-095VPrpTtN4QMOqROA"
		value := "東京都港区芝公園４丁目２−８"

		d, err := NewDisclosureWithSalt(salt, "street_address", value, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		if parsed.ClaimValue != value {
			t.Errorf("ClaimValue = %v, want %v", parsed.ClaimValue, value)
		}
	})
}

// TestRFC9901_SDListKey tests the constant for array element placeholders.
func TestRFC9901_SDListKey(t *testing.T) {
	// Array element digests use "..." as the key
	if SDListKey != "..." {
		t.Errorf("SDListKey = %q, want %q", SDListKey, "...")
	}
}

// =============================================================================
// Appendix A Tests - Comprehensive examples from RFC 9901
// =============================================================================

// TestRFC9901AppendixA1_SimpleStructured tests the simple structured SD-JWT from Appendix A.1.
// This example shows basic identity claims with Japanese values and decoy digests.
func TestRFC9901AppendixA1_SimpleStructured(t *testing.T) {
	// Appendix A.1 demonstrates:
	// 1. Basic identity claims (sub, given_name, family_name, email, etc.)
	// 2. Unicode values (Japanese characters)
	// 3. Address as a nested object
	// 4. Decoy digests to hide number of claims

	t.Run("basic_claims_structure", func(t *testing.T) {
		// Test basic SD-JWT claims structure
		claims := map[string]any{
			"sub":          "user_42",
			"given_name":   "太郎",
			"family_name":  "山田",
			"email":        "taro.yamada@example.com",
			"phone_number": "+81-80-1234-5678",
			"address": map[string]any{
				"street_address": "東京都港区芝公園４丁目２−８",
				"locality":       "東京都",
				"region":         "港区",
				"country":        "JP",
			},
			"birthdate": "1980-01-01",
		}

		// All claims should be valid for disclosure
		for name := range claims {
			err := ValidateDisclosureClaimName(name)
			if err != nil {
				t.Errorf("Claim %q should be valid: %v", name, err)
			}
		}
	})

	t.Run("japanese_unicode_support", func(t *testing.T) {
		// Test Japanese characters in disclosures
		d, err := NewDisclosure("given_name", "太郎", HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		if parsed.ClaimValue != "太郎" {
			t.Errorf("ClaimValue = %v, want 太郎", parsed.ClaimValue)
		}
	})

	t.Run("decoy_digests", func(t *testing.T) {
		// Test decoy digest generation
		var decoys []string
		for i := 0; i < 3; i++ {
			decoy, err := GenerateDecoyDigest(HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to generate decoy: %v", err)
			}
			decoys = append(decoys, decoy)
		}

		// All decoys should be unique
		seen := make(map[string]bool)
		for _, d := range decoys {
			if seen[d] {
				t.Error("Decoy digests should be unique")
			}
			seen[d] = true
		}

		// Decoys should look like real digests (same length)
		for _, d := range decoys {
			if len(d) != 43 { // SHA-256 base64url length
				t.Errorf("Decoy length = %d, want 43", len(d))
			}
		}
	})

	t.Run("nested_address_disclosure", func(t *testing.T) {
		// Test nested address object as disclosure
		address := map[string]any{
			"street_address": "東京都港区芝公園４丁目２−８",
			"locality":       "東京都",
			"region":         "港区",
			"country":        "JP",
		}

		d, err := NewDisclosure("address", address, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		parsedAddr, ok := parsed.ClaimValue.(map[string]any)
		if !ok {
			t.Fatal("ClaimValue should be a map")
		}

		if parsedAddr["country"] != "JP" {
			t.Errorf("country = %v, want JP", parsedAddr["country"])
		}
	})
}

// TestRFC9901AppendixA2_ComplexStructured tests the complex structured SD-JWT from Appendix A.2.
// This example uses the OIDC Identity Assurance verified_claims structure.
func TestRFC9901AppendixA2_ComplexStructured(t *testing.T) {
	// Appendix A.2 demonstrates:
	// 1. OIDC IDA verified_claims structure
	// 2. verification object with trust_framework, time, evidence
	// 3. Deeply nested selective disclosure
	// 4. Array elements as disclosures

	t.Run("verified_claims_structure", func(t *testing.T) {
		// Test the verified_claims structure from OIDC IDA
		verifiedClaims := map[string]any{
			"verification": map[string]any{
				"trust_framework": "de_aml",
				"time":            "2012-04-23T18:25:43.511+01:00",
				"verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
				"evidence": []any{
					map[string]any{
						"type":   "document",
						"method": "pipp",
						"document": map[string]any{
							"type":        "idcard",
							"issuer_name": "Stadt Augsburg",
							"issuer_country": "DE",
							"number":      "53554554",
						},
					},
				},
			},
			"claims": map[string]any{
				"given_name":  "Max",
				"family_name": "Müller",
				"birthdate":   "1956-01-28",
				"place_of_birth": map[string]any{
					"country":  "DE",
					"locality": "Musterstadt",
				},
				"nationalities": []any{"DE"},
				"address": map[string]any{
					"locality":       "Maxstadt",
					"postal_code":    "12344",
					"country":        "DE",
					"street_address": "Weidenstraße 22",
				},
			},
		}

		// Create disclosure for entire verified_claims
		d, err := NewDisclosure("verified_claims", verifiedClaims, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		// Verify round-trip
		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		if parsed.ClaimName != "verified_claims" {
			t.Errorf("ClaimName = %q, want verified_claims", parsed.ClaimName)
		}
	})

	t.Run("nested_evidence_array", func(t *testing.T) {
		// Test array element disclosure for evidence
		evidence := map[string]any{
			"type":   "document",
			"method": "pipp",
		}

		// Array elements use 2-element format: [salt, value]
		d, err := NewArrayElementDisclosure(evidence, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create array element disclosure: %v", err)
		}

		if !d.IsArrayElement() {
			t.Error("Should be an array element disclosure")
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse disclosure: %v", err)
		}

		parsedEvidence, ok := parsed.ClaimValue.(map[string]any)
		if !ok {
			t.Fatal("ClaimValue should be a map")
		}

		if parsedEvidence["type"] != "document" {
			t.Errorf("type = %v, want document", parsedEvidence["type"])
		}
	})

	t.Run("nationality_array_elements", func(t *testing.T) {
		// Test nationalities as array element disclosures
		nationalities := []string{"DE", "FR"}

		for _, nat := range nationalities {
			d, err := NewArrayElementDisclosure(nat, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to create disclosure for %s: %v", nat, err)
			}

			if !d.IsArrayElement() {
				t.Error("Should be array element")
			}

			parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if parsed.ClaimValue != nat {
				t.Errorf("Value = %v, want %s", parsed.ClaimValue, nat)
			}
		}
	})

	t.Run("german_umlauts", func(t *testing.T) {
		// Test German umlauts (special characters)
		d, err := NewDisclosure("family_name", "Müller", HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse: %v", err)
		}

		if parsed.ClaimValue != "Müller" {
			t.Errorf("ClaimValue = %v, want Müller", parsed.ClaimValue)
		}
	})
}

// TestRFC9901AppendixA3_SDJWTVCExample tests the SD-JWT VC example from Appendix A.3.
// This tests SD-JWT based Verifiable Credentials.
func TestRFC9901AppendixA3_SDJWTVCExample(t *testing.T) {
	// Appendix A.3 demonstrates:
	// 1. SD-JWT VC with vct claim
	// 2. Credential status
	// 3. cnf claim for key binding
	// 4. Standard VC claims (iss, nbf, exp)

	t.Run("vc_reserved_claims", func(t *testing.T) {
		// These claims should NOT be selectively disclosable per draft-ietf-oauth-sd-jwt-vc
		// They should be in the JWT payload directly
		reservedClaims := []string{"iss", "nbf", "exp", "cnf", "vct", "status"}

		// All are valid claim names (not _sd or ...)
		for _, claim := range reservedClaims {
			err := ValidateDisclosureClaimName(claim)
			if err != nil {
				t.Errorf("Claim %q should be a valid name: %v", claim, err)
			}
		}
	})

	t.Run("vc_disclosable_claims", func(t *testing.T) {
		// These claims CAN be selectively disclosable
		disclosableClaims := map[string]any{
			"given_name":   "John",
			"family_name":  "Doe",
			"email":        "john.doe@example.com",
			"phone_number": "+1-202-555-0101",
			"address": map[string]any{
				"street_address": "123 Main St",
				"locality":       "Anytown",
				"region":         "Anystate",
				"country":        "US",
			},
			"birthdate": "1990-01-01",
			"age_over_18": true,
			"age_over_21": true,
		}

		for name, value := range disclosableClaims {
			d, err := NewDisclosure(name, value, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to create disclosure for %s: %v", name, err)
			}

			parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to parse disclosure for %s: %v", name, err)
			}

			if parsed.ClaimName != name {
				t.Errorf("ClaimName = %q, want %q", parsed.ClaimName, name)
			}
		}
	})

	t.Run("cnf_key_binding", func(t *testing.T) {
		// Test cnf claim structure for key binding
		cnf := map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"x":   "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
				"y":   "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
			},
		}

		// cnf is typically NOT disclosed but part of JWT payload
		d, err := NewDisclosure("cnf", cnf, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse: %v", err)
		}

		parsedCnf, ok := parsed.ClaimValue.(map[string]any)
		if !ok {
			t.Fatal("ClaimValue should be a map")
		}

		jwk, ok := parsedCnf["jwk"].(map[string]any)
		if !ok {
			t.Fatal("jwk should be a map")
		}

		if jwk["kty"] != "EC" {
			t.Errorf("kty = %v, want EC", jwk["kty"])
		}
	})

	t.Run("status_claim", func(t *testing.T) {
		// Test status claim structure for revocation
		status := map[string]any{
			"status_list": map[string]any{
				"idx": float64(0),
				"uri": "https://example.com/statuslists/1",
			},
		}

		d, err := NewDisclosure("status", status, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to create disclosure: %v", err)
		}

		parsed, err := ParseDisclosure(d.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Failed to parse: %v", err)
		}

		parsedStatus, ok := parsed.ClaimValue.(map[string]any)
		if !ok {
			t.Fatal("ClaimValue should be a map")
		}

		statusList, ok := parsedStatus["status_list"].(map[string]any)
		if !ok {
			t.Fatal("status_list should be a map")
		}

		if statusList["uri"] != "https://example.com/statuslists/1" {
			t.Errorf("uri = %v, want https://example.com/statuslists/1", statusList["uri"])
		}
	})
}

// TestRFC9901_EndToEndVerification tests end-to-end SD-JWT creation and parsing.
func TestRFC9901_EndToEndVerification(t *testing.T) {
	// Test creating disclosures, adding them to an SD-JWT, and verifying

	t.Run("disclosure_to_digest_mapping", func(t *testing.T) {
		// Create multiple disclosures
		disclosures := []struct {
			name  string
			value any
		}{
			{"given_name", "John"},
			{"family_name", "Doe"},
			{"email", "john@example.com"},
		}

		digestMap := make(map[string]*Disclosure)
		var sdDigests []string

		for _, d := range disclosures {
			disc, err := NewDisclosure(d.name, d.value, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to create disclosure: %v", err)
			}

			digestMap[disc.Digest] = disc
			sdDigests = append(sdDigests, disc.Digest)
		}

		// Verify each digest maps to the correct disclosure
		for digest, disc := range digestMap {
			// Re-parse the disclosure and verify digest matches
			parsed, err := ParseDisclosure(disc.Encoded, HashAlgSHA256)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if parsed.Digest != digest {
				t.Errorf("Digest mismatch: parsed=%q, expected=%q", parsed.Digest, digest)
			}
		}
	})

	t.Run("hash_algorithm_consistency", func(t *testing.T) {
		// Same disclosure should produce same digest
		salt := "test_salt_123"
		name := "test_claim"
		value := "test_value"

		d1, _ := NewDisclosureWithSalt(salt, name, value, HashAlgSHA256)
		d2, _ := NewDisclosureWithSalt(salt, name, value, HashAlgSHA256)

		if d1.Digest != d2.Digest {
			t.Error("Same input should produce same digest")
		}

		if d1.Encoded != d2.Encoded {
			t.Error("Same input should produce same encoding")
		}
	})
}
