package issuer

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	s, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	return NewIssuer(s)
}

// TestFlatDisclosure verifies that an entire nested object can be disclosed as one unit.
// This matches RFC 9901 Section 6.1 - Flat SD-JWT pattern.
func TestFlatDisclosure(t *testing.T) {
	iss := newTestIssuer(t)

	// Claims with nested address object
	claims := map[string]any{
		"sub":          "user_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
		"birthdate": "1940-01-01",
	}

	// Frame: make individual claims SD, but address as a whole (flat)
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "email", "phone_number", "address", "birthdate"},
		// No nested frame for address - it's disclosed as a single unit
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have disclosures
	if len(sdJWT.Disclosures) != 6 {
		t.Errorf("Expected 6 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Parse the JWT to verify structure
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)

	// Verify _sd array exists with correct number of entries
	sdArray, ok := payload["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd array in payload")
	}
	if len(sdArray) != 6 {
		t.Errorf("Expected 6 digests in _sd, got %d", len(sdArray))
	}

	// Verify _sd_alg is present
	if payload["_sd_alg"] != "sha-256" {
		t.Errorf("Expected _sd_alg=sha-256, got %v", payload["_sd_alg"])
	}

	// Verify address is NOT in the JWT payload directly (it's hidden in _sd)
	if _, exists := payload["address"]; exists {
		t.Error("address should not be in payload directly - it should be in _sd")
	}

	// Find and verify the address disclosure contains the full object
	foundAddress := false
	for _, d := range sdJWT.Disclosures {
		if d.ClaimName == "address" {
			foundAddress = true
			addrMap, ok := d.ClaimValue.(map[string]any)
			if !ok {
				t.Error("address disclosure value should be a map")
			} else {
				if addrMap["street_address"] != "123 Main St" {
					t.Error("address disclosure should contain street_address")
				}
				if addrMap["locality"] != "Anytown" {
					t.Error("address disclosure should contain locality")
				}
			}
			break
		}
	}
	if !foundAddress {
		t.Error("Expected to find address disclosure")
	}
}

// TestStructuredDisclosure verifies that nested object claims can be individually disclosed.
// This matches RFC 9901 Section 6.2 - Structured SD-JWT pattern.
func TestStructuredDisclosure(t *testing.T) {
	iss := newTestIssuer(t)

	// Claims with nested address object
	claims := map[string]any{
		"sub":          "user_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
		"birthdate": "1940-01-01",
	}

	// Frame: make top-level claims SD and address sub-claims individually SD
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "email", "phone_number", "birthdate"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD: []string{"street_address", "locality", "region", "country"},
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 9 disclosures (5 top-level + 4 address sub-claims)
	if len(sdJWT.Disclosures) != 9 {
		t.Errorf("Expected 9 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Parse the JWT to verify structure
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)

	// Verify address exists in payload with _sd array
	addressClaim, ok := payload["address"].(map[string]any)
	if !ok {
		t.Fatal("Expected address object in payload")
	}

	// Verify address has its own _sd array
	addrSD, ok := addressClaim["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd array in address")
	}
	if len(addrSD) != 4 {
		t.Errorf("Expected 4 digests in address._sd, got %d", len(addrSD))
	}

	// Verify individual address fields are NOT directly in the address object
	if _, exists := addressClaim["street_address"]; exists {
		t.Error("street_address should not be directly in address - it should be in _sd")
	}

	// Verify disclosures for address sub-claims exist
	addressClaims := []string{"street_address", "locality", "region", "country"}
	for _, claimName := range addressClaims {
		found := false
		for _, d := range sdJWT.Disclosures {
			if d.ClaimName == claimName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected disclosure for %s", claimName)
		}
	}
}

// TestRecursiveDisclosure verifies that both parent and child claims can be SD.
// This matches RFC 9901 Section 6.3 - SD-JWT with Recursive Disclosures.
func TestRecursiveDisclosure(t *testing.T) {
	iss := newTestIssuer(t)

	// Claims with nested address object
	claims := map[string]any{
		"sub":          "user_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
		"birthdate": "1940-01-01",
	}

	// Frame: address itself is SD, AND its sub-claims are also SD
	// This is the recursive pattern
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "email", "phone_number", "address", "birthdate"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD: []string{"street_address", "locality", "region", "country"},
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 10 disclosures (6 top-level including address + 4 address sub-claims)
	if len(sdJWT.Disclosures) != 10 {
		t.Errorf("Expected 10 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Find the address disclosure and verify it has _sd inside
	var addressDisclosure *sdjwt.Disclosure
	for i, d := range sdJWT.Disclosures {
		if d.ClaimName == "address" {
			addressDisclosure = &sdJWT.Disclosures[i]
			break
		}
	}

	if addressDisclosure == nil {
		t.Fatal("Expected address disclosure")
	}

	// The address disclosure should contain an object with _sd array
	addrValue, ok := addressDisclosure.ClaimValue.(map[string]any)
	if !ok {
		t.Fatal("address disclosure value should be a map")
	}

	// In recursive mode, the address object itself has _sd with its sub-claim digests
	addrSD, ok := addrValue["_sd"].([]string)
	if !ok {
		// Try []any
		addrSDArr, ok := addrValue["_sd"].([]any)
		if !ok {
			t.Fatal("Expected _sd array in address disclosure value")
		}
		if len(addrSDArr) != 4 {
			t.Errorf("Expected 4 digests in address._sd, got %d", len(addrSDArr))
		}
	} else {
		if len(addrSD) != 4 {
			t.Errorf("Expected 4 digests in address._sd, got %d", len(addrSD))
		}
	}
}

// TestArrayElementDisclosure verifies that individual array elements can be disclosed.
// This matches RFC 9901 Section 5 - nationalities array pattern.
func TestArrayElementDisclosure(t *testing.T) {
	iss := newTestIssuer(t)

	// Claims with nationalities array
	claims := map[string]any{
		"sub":           "user_42",
		"given_name":    "John",
		"family_name":   "Doe",
		"nationalities": []any{"US", "DE"},
	}

	// Frame: make nationalities array elements individually SD
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"nationalities": {
				SD: []string{"0", "1"}, // Array indices as strings
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 4 disclosures (2 top-level + 2 array elements)
	if len(sdJWT.Disclosures) != 4 {
		t.Errorf("Expected 4 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Parse the JWT to verify structure
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)

	// Verify nationalities array exists with digest placeholders
	natArr, ok := payload["nationalities"].([]any)
	if !ok {
		t.Fatal("Expected nationalities array in payload")
	}

	if len(natArr) != 2 {
		t.Fatalf("Expected 2 elements in nationalities, got %d", len(natArr))
	}

	// Each element should be {"...": "digest"}
	for i, elem := range natArr {
		elemMap, ok := elem.(map[string]any)
		if !ok {
			t.Errorf("Element %d should be a map with '...' key", i)
			continue
		}
		if _, hasEllipsis := elemMap["..."]; !hasEllipsis {
			t.Errorf("Element %d should have '...' key for digest placeholder", i)
		}
	}

	// Verify array element disclosures (they have empty ClaimName)
	arrayDisclosures := 0
	for _, d := range sdJWT.Disclosures {
		if d.ClaimName == "" {
			arrayDisclosures++
			// Value should be "US" or "DE"
			if d.ClaimValue != "US" && d.ClaimValue != "DE" {
				t.Errorf("Array disclosure value should be US or DE, got %v", d.ClaimValue)
			}
		}
	}
	if arrayDisclosures != 2 {
		t.Errorf("Expected 2 array element disclosures, got %d", arrayDisclosures)
	}
}

// TestFullArrayDisclosure verifies that an entire array can be disclosed as one unit.
// Similar to flat disclosure but for arrays.
func TestFullArrayDisclosure(t *testing.T) {
	iss := newTestIssuer(t)

	// Claims with nationalities array
	claims := map[string]any{
		"sub":           "user_42",
		"given_name":    "John",
		"family_name":   "Doe",
		"nationalities": []any{"US", "DE"},
	}

	// Frame: make nationalities array itself SD (not individual elements)
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "nationalities"},
		// No nested frame for nationalities - it's disclosed as a whole array
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 3 disclosures (all at top level)
	if len(sdJWT.Disclosures) != 3 {
		t.Errorf("Expected 3 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Find the nationalities disclosure
	var natDisclosure *sdjwt.Disclosure
	for i, d := range sdJWT.Disclosures {
		if d.ClaimName == "nationalities" {
			natDisclosure = &sdJWT.Disclosures[i]
			break
		}
	}

	if natDisclosure == nil {
		t.Fatal("Expected nationalities disclosure")
	}

	// The disclosure should contain the full array
	natArr, ok := natDisclosure.ClaimValue.([]any)
	if !ok {
		t.Fatal("nationalities disclosure value should be an array")
	}

	if len(natArr) != 2 {
		t.Errorf("Expected 2 elements in nationalities disclosure, got %d", len(natArr))
	}

	if natArr[0] != "US" || natArr[1] != "DE" {
		t.Errorf("nationalities disclosure should be [US, DE], got %v", natArr)
	}

	// Parse JWT to verify nationalities is not in payload
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	if _, exists := payload["nationalities"]; exists {
		t.Error("nationalities should not be in payload directly - it should be in _sd")
	}
}

// TestDecoyDigests verifies that decoy digests can be added for privacy.
// This matches RFC 9901 Appendix A.1 pattern.
func TestDecoyDigests(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	// Frame with decoy digests
	frame := &sdjwt.DisclosureFrame{
		SD:      []string{"given_name"},
		SDDecoy: 3, // Add 3 decoy digests
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 1 actual disclosure
	if len(sdJWT.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(sdJWT.Disclosures))
	}

	// Parse JWT to verify _sd has 4 entries (1 real + 3 decoys)
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	sdArray, ok := payload["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd array in payload")
	}

	if len(sdArray) != 4 {
		t.Errorf("Expected 4 entries in _sd (1 real + 3 decoys), got %d", len(sdArray))
	}

	// Verify only 1 digest matches a disclosure
	matchCount := 0
	disclosureDigest := sdJWT.Disclosures[0].Digest
	for _, d := range sdArray {
		if d == disclosureDigest {
			matchCount++
		}
	}
	if matchCount != 1 {
		t.Errorf("Expected exactly 1 matching digest, got %d", matchCount)
	}
}

// TestNestedDecoyDigests verifies that decoy digests work at nested levels.
func TestNestedDecoyDigests(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub": "user_42",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
		},
	}

	// Frame with decoys at nested level
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD:      []string{"street_address"},
				SDDecoy: 2, // Add 2 decoys in address._sd
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 1 disclosure
	if len(sdJWT.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(sdJWT.Disclosures))
	}

	// Parse JWT to verify address._sd has 3 entries (1 real + 2 decoys)
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	address, ok := payload["address"].(map[string]any)
	if !ok {
		t.Fatal("Expected address object in payload")
	}

	addrSD, ok := address["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd array in address")
	}

	if len(addrSD) != 3 {
		t.Errorf("Expected 3 entries in address._sd (1 real + 2 decoys), got %d", len(addrSD))
	}

	// Verify locality is still directly in address (not SD)
	if address["locality"] != "Anytown" {
		t.Error("locality should be directly in address")
	}
}

// TestArrayDecoyDigests verifies that decoy digests work for arrays.
func TestArrayDecoyDigests(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":           "user_42",
		"nationalities": []any{"US", "DE"},
	}

	// Frame with array element SD and decoys
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"nationalities": {
				SD:      []string{"0"}, // Only first element is SD
				SDDecoy: 2,             // Add 2 decoys
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify we have 1 disclosure
	if len(sdJWT.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(sdJWT.Disclosures))
	}

	// Parse JWT to verify array structure
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	natArr, ok := payload["nationalities"].([]any)
	if !ok {
		t.Fatal("Expected nationalities array in payload")
	}

	// Should have: 1 digest placeholder (element 0), "DE" (element 1), 2 decoy placeholders
	if len(natArr) != 4 {
		t.Errorf("Expected 4 elements in nationalities (1 SD + 1 plain + 2 decoys), got %d", len(natArr))
	}

	// First element should be digest placeholder
	firstElem, ok := natArr[0].(map[string]any)
	if !ok {
		t.Error("First element should be a digest placeholder")
	} else if _, hasEllipsis := firstElem["..."]; !hasEllipsis {
		t.Error("First element should have '...' key")
	}

	// Second element should be "DE" directly
	if natArr[1] != "DE" {
		t.Errorf("Second element should be DE, got %v", natArr[1])
	}
}

// TestComplexNestedStructure verifies complex nested structures like OIDC IDA verified_claims.
// This matches RFC 9901 Appendix A.2 pattern.
func TestComplexNestedStructure(t *testing.T) {
	iss := newTestIssuer(t)

	// Complex nested claims similar to OIDC IDA verified_claims
	claims := map[string]any{
		"sub": "user_42",
		"verified_claims": map[string]any{
			"verification": map[string]any{
				"trust_framework": "de_aml",
				"evidence": []any{
					map[string]any{
						"type":   "document",
						"method": "pipp",
						"document": map[string]any{
							"type": "idcard",
						},
					},
				},
			},
			"claims": map[string]any{
				"given_name":  "Max",
				"family_name": "Mustermann",
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
		},
	}

	// Frame for complex nested structure
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"verified_claims": {
				Nested: map[string]*sdjwt.DisclosureFrame{
					"verification": {
						SD: []string{"trust_framework"},
						Nested: map[string]*sdjwt.DisclosureFrame{
							"evidence": {
								SD: []string{"0"}, // First evidence item is SD
							},
						},
					},
					"claims": {
						SD: []string{"given_name", "family_name", "birthdate", "place_of_birth", "nationalities", "address"},
					},
				},
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Should have: trust_framework, evidence[0], given_name, family_name, birthdate,
	// place_of_birth, nationalities, address = 8 disclosures
	if len(sdJWT.Disclosures) != 8 {
		t.Errorf("Expected 8 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Parse JWT to verify structure
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)

	verifiedClaims, ok := payload["verified_claims"].(map[string]any)
	if !ok {
		t.Fatal("Expected verified_claims object")
	}

	verification, ok := verifiedClaims["verification"].(map[string]any)
	if !ok {
		t.Fatal("Expected verification object")
	}

	// Verify trust_framework is not directly in verification (it's SD)
	if _, exists := verification["trust_framework"]; exists {
		t.Error("trust_framework should not be directly in verification")
	}

	// Verify verification has _sd array
	verificationSD, ok := verification["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd array in verification")
	}
	if len(verificationSD) < 1 {
		t.Error("verification._sd should have at least 1 entry")
	}

	// Verify claims has _sd array
	claimsObj, ok := verifiedClaims["claims"].(map[string]any)
	if !ok {
		t.Fatal("Expected claims object")
	}
	claimsSD, ok := claimsObj["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd array in claims")
	}
	if len(claimsSD) != 6 {
		t.Errorf("claims._sd should have 6 entries, got %d", len(claimsSD))
	}
}

// TestDeepNesting verifies SD-JWT works with deep nesting levels.
func TestDeepNesting(t *testing.T) {
	iss := newTestIssuer(t)

	// 4 levels of nesting
	claims := map[string]any{
		"sub": "user_42",
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": map[string]any{
					"level4": map[string]any{
						"secret": "deep_value",
					},
				},
			},
		},
	}

	// Make the deepest claim SD
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"level1": {
				Nested: map[string]*sdjwt.DisclosureFrame{
					"level2": {
						Nested: map[string]*sdjwt.DisclosureFrame{
							"level3": {
								Nested: map[string]*sdjwt.DisclosureFrame{
									"level4": {
										SD: []string{"secret"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	if len(sdJWT.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(sdJWT.Disclosures))
	}

	// Verify the deep claim is disclosed
	if sdJWT.Disclosures[0].ClaimName != "secret" {
		t.Errorf("Expected disclosure for 'secret', got '%s'", sdJWT.Disclosures[0].ClaimName)
	}
	if sdJWT.Disclosures[0].ClaimValue != "deep_value" {
		t.Errorf("Expected 'deep_value', got '%v'", sdJWT.Disclosures[0].ClaimValue)
	}

	// Parse and verify deep structure
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	level1, ok := payload["level1"].(map[string]any)
	if !ok {
		t.Fatal("Expected level1 object")
	}
	level2, ok := level1["level2"].(map[string]any)
	if !ok {
		t.Fatal("Expected level2 object")
	}
	level3, ok := level2["level3"].(map[string]any)
	if !ok {
		t.Fatal("Expected level3 object")
	}
	level4, ok := level3["level4"].(map[string]any)
	if !ok {
		t.Fatal("Expected level4 object")
	}

	// level4 should have _sd array
	level4SD, ok := level4["_sd"].([]any)
	if !ok {
		t.Fatal("Expected _sd in level4")
	}
	if len(level4SD) != 1 {
		t.Errorf("Expected 1 entry in level4._sd, got %d", len(level4SD))
	}
}

// TestMixedArrayContent verifies arrays with both SD and non-SD elements.
func TestMixedArrayContent(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":    "user_42",
		"emails": []any{"primary@example.com", "secondary@example.com", "backup@example.com"},
	}

	// Make only some array elements SD
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"emails": {
				SD: []string{"0", "2"}, // First and third are SD, second is not
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	if len(sdJWT.Disclosures) != 2 {
		t.Errorf("Expected 2 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Parse JWT
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	emails, ok := payload["emails"].([]any)
	if !ok {
		t.Fatal("Expected emails array")
	}

	if len(emails) != 3 {
		t.Fatalf("Expected 3 elements in emails, got %d", len(emails))
	}

	// Element 0 should be digest placeholder
	elem0, ok := emails[0].(map[string]any)
	if !ok {
		t.Error("Element 0 should be digest placeholder")
	} else if _, hasEllipsis := elem0["..."]; !hasEllipsis {
		t.Error("Element 0 should have '...' key")
	}

	// Element 1 should be the actual value
	if emails[1] != "secondary@example.com" {
		t.Errorf("Element 1 should be 'secondary@example.com', got %v", emails[1])
	}

	// Element 2 should be digest placeholder
	elem2, ok := emails[2].(map[string]any)
	if !ok {
		t.Error("Element 2 should be digest placeholder")
	} else if _, hasEllipsis := elem2["..."]; !hasEllipsis {
		t.Error("Element 2 should have '...' key")
	}
}

// TestHashAlgorithms verifies different hash algorithms work.
func TestHashAlgorithms(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	algorithms := []string{"sha-256", "sha-384", "sha-512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			opts := &IssueOptions{
				HashAlgorithm: alg,
			}

			sdJWT, err := iss.IssueWithFrame(claims, frame, opts)
			if err != nil {
				t.Fatalf("IssueWithFrame failed: %v", err)
			}

			if sdJWT.HashAlgorithm != alg {
				t.Errorf("Expected hash algorithm %s, got %s", alg, sdJWT.HashAlgorithm)
			}

			// Verify _sd_alg in payload
			payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
			if payload["_sd_alg"] != alg {
				t.Errorf("Expected _sd_alg=%s, got %v", alg, payload["_sd_alg"])
			}

			// Verify disclosure digest length matches algorithm
			d := sdJWT.Disclosures[0]
			expectedLengthMap := map[string]int{
				"sha-256": 43, // Base64URL of 32 bytes
				"sha-384": 64, // Base64URL of 48 bytes
				"sha-512": 86, // Base64URL of 64 bytes
			}
			expectedLen := expectedLengthMap[alg]
			if len(d.Digest) != expectedLen {
				t.Errorf("Expected digest length %d for %s, got %d", expectedLen, alg, len(d.Digest))
			}
		})
	}
}

// TestJWTTypeHeader verifies custom type headers can be set.
func TestJWTTypeHeader(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	opts := &IssueOptions{
		Type: "sd+jwt",
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, opts)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Parse JWT header
	parts := strings.Split(sdJWT.IssuerSignedJWT, ".")
	if len(parts) != 3 {
		t.Fatal("JWT should have 3 parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}

	if header["typ"] != "sd+jwt" {
		t.Errorf("Expected typ=sd+jwt, got %v", header["typ"])
	}
}

// TestHolderBinding verifies holder public key binding.
func TestHolderBinding(t *testing.T) {
	issuerSigner, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to create issuer signer: %v", err)
	}

	holderSigner, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to create holder signer: %v", err)
	}

	iss := NewIssuer(issuerSigner)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	// Create holder JWK
	holderPub, ok := holderSigner.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("holder signer public key is not ECDSA")
	}
	holderJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(holderPub.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(holderPub.Y.Bytes()),
	}
	holderJWKBytes, _ := json.Marshal(holderJWK)

	opts := &IssueOptions{
		HolderPublicKey: holderJWKBytes,
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, opts)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// Verify cnf claim in payload
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		t.Fatal("Expected cnf claim")
	}

	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		t.Fatal("Expected jwk in cnf")
	}

	if jwk["kty"] != "EC" {
		t.Errorf("Expected kty=EC, got %v", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("Expected crv=P-256, got %v", jwk["crv"])
	}
}

// TestNoDisclosures verifies behavior when no claims are SD.
func TestNoDisclosures(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	// Empty frame - no SD claims
	frame := &sdjwt.DisclosureFrame{}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// No disclosures
	if len(sdJWT.Disclosures) != 0 {
		t.Errorf("Expected 0 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Parse JWT
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)

	// Should not have _sd or _sd_alg
	if _, exists := payload["_sd"]; exists {
		t.Error("_sd should not be in payload when no disclosures")
	}
	if _, exists := payload["_sd_alg"]; exists {
		t.Error("_sd_alg should not be in payload when no disclosures")
	}

	// Claims should be directly in payload
	if payload["given_name"] != "John" {
		t.Error("given_name should be directly in payload")
	}
}

// TestNilFrame verifies behavior with nil frame (no SD).
func TestNilFrame(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	// nil frame
	sdJWT, err := iss.IssueWithFrame(claims, nil, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	// No disclosures
	if len(sdJWT.Disclosures) != 0 {
		t.Errorf("Expected 0 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Claims should be directly in payload
	payload := parseJWTPayload(t, sdJWT.IssuerSignedJWT)
	if payload["given_name"] != "John" {
		t.Error("given_name should be directly in payload")
	}
}

// TestSerialization verifies SD-JWT serialization formats.
func TestSerialization(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	t.Run("CompactSerialization", func(t *testing.T) {
		serialized := sdJWT.Serialize()

		// Should have JWT + disclosures + trailing ~
		parts := strings.Split(serialized, "~")
		// JWT has 3 parts separated by ., plus 2 disclosures, plus empty string at end
		if len(parts) != 4 { // JWT, disclosure1, disclosure2, empty
			t.Errorf("Expected 4 parts, got %d", len(parts))
		}

		// First part should be JWT (has dots)
		if !strings.Contains(parts[0], ".") {
			t.Error("First part should be JWT")
		}

		// Last part should be empty (trailing ~)
		if parts[len(parts)-1] != "" {
			t.Error("Should have trailing ~")
		}
	})

	t.Run("FlattenJSONSerialization", func(t *testing.T) {
		jsonStr, err := sdJWT.SerializeFlattenJSON()
		if err != nil {
			t.Fatalf("SerializeFlattenJSON failed: %v", err)
		}

		var flat map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &flat); err != nil {
			t.Fatalf("Failed to parse JSON: %v", err)
		}

		// Should have "protected" and "header"
		if _, ok := flat["protected"]; !ok {
			t.Error("Expected 'protected' in flattened JSON")
		}
		header, ok := flat["header"].(map[string]any)
		if !ok {
			t.Fatal("Expected 'header' object in flattened JSON")
		}
		disclosures, ok := header["disclosures"].([]any)
		if !ok {
			t.Error("Expected 'disclosures' array in flattened JSON header")
		} else if len(disclosures) != 2 {
			t.Errorf("Expected 2 disclosures, got %d", len(disclosures))
		}
	})

	t.Run("GeneralJSONSerialization", func(t *testing.T) {
		jsonStr, err := sdJWT.SerializeGeneralJSON()
		if err != nil {
			t.Fatalf("SerializeGeneralJSON failed: %v", err)
		}

		var general map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &general); err != nil {
			t.Fatalf("Failed to parse JSON: %v", err)
		}

		// Should have "signatures" array
		sigs, ok := general["signatures"].([]any)
		if !ok {
			t.Error("Expected 'signatures' array in general JSON")
		}
		if len(sigs) < 1 {
			t.Error("Expected at least 1 signature")
		}

		firstSig, ok := sigs[0].(map[string]any)
		if !ok {
			t.Fatal("Expected first signature object")
		}
		header, ok := firstSig["header"].(map[string]any)
		if !ok {
			t.Fatal("Expected 'header' object in general JSON signature")
		}
		disclosures, ok := header["disclosures"].([]any)
		if !ok {
			t.Error("Expected 'disclosures' array in general JSON header")
		} else if len(disclosures) != 2 {
			t.Errorf("Expected 2 disclosures, got %d", len(disclosures))
		}
	})
}

// TestAllClaimTypesSD verifies different claim value types can be made SD.
func TestAllClaimTypesSD(t *testing.T) {
	iss := newTestIssuer(t)

	claims := map[string]any{
		"sub":          "user_42",
		"string_claim": "hello",
		"number_claim": 42.5,
		"int_claim":    100,
		"bool_claim":   true,
		"null_claim":   nil,
		"array_claim":  []any{"a", "b", "c"},
		"object_claim": map[string]any{"key": "value"},
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"string_claim", "number_claim", "int_claim", "bool_claim", "null_claim", "array_claim", "object_claim"},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("IssueWithFrame failed: %v", err)
	}

	if len(sdJWT.Disclosures) != 7 {
		t.Errorf("Expected 7 disclosures, got %d", len(sdJWT.Disclosures))
	}

	// Verify each disclosure
	discMap := make(map[string]sdjwt.Disclosure)
	for _, d := range sdJWT.Disclosures {
		discMap[d.ClaimName] = d
	}

	// String
	if discMap["string_claim"].ClaimValue != "hello" {
		t.Errorf("string_claim should be 'hello', got %v", discMap["string_claim"].ClaimValue)
	}

	// Number (float)
	if discMap["number_claim"].ClaimValue != 42.5 {
		t.Errorf("number_claim should be 42.5, got %v", discMap["number_claim"].ClaimValue)
	}

	// Int (might be float64 after JSON round-trip)
	numVal, ok := discMap["int_claim"].ClaimValue.(float64)
	if !ok {
		numVal2, ok2 := discMap["int_claim"].ClaimValue.(int)
		if !ok2 || numVal2 != 100 {
			t.Errorf("int_claim should be 100, got %v", discMap["int_claim"].ClaimValue)
		}
	} else if numVal != 100 {
		t.Errorf("int_claim should be 100, got %v", numVal)
	}

	// Bool
	if discMap["bool_claim"].ClaimValue != true {
		t.Errorf("bool_claim should be true, got %v", discMap["bool_claim"].ClaimValue)
	}

	// Null
	if discMap["null_claim"].ClaimValue != nil {
		t.Errorf("null_claim should be nil, got %v", discMap["null_claim"].ClaimValue)
	}

	// Array
	arrVal, ok := discMap["array_claim"].ClaimValue.([]any)
	if !ok {
		t.Error("array_claim should be []any")
	} else if len(arrVal) != 3 {
		t.Errorf("array_claim should have 3 elements, got %d", len(arrVal))
	}

	// Object
	objVal, ok := discMap["object_claim"].ClaimValue.(map[string]any)
	if !ok {
		t.Error("object_claim should be map[string]any")
	} else if objVal["key"] != "value" {
		t.Errorf("object_claim.key should be 'value', got %v", objVal["key"])
	}
}

// Helper function to parse JWT payload
func parseJWTPayload(t *testing.T, jwtStr string) map[string]any {
	t.Helper()

	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatal("JWT should have 3 parts")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}

	return payload
}
