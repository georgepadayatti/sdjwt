package holder

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// TestPresentWithFrameFlatDisclosure tests presenting from a flat disclosure SD-JWT.
func TestPresentWithFrameFlatDisclosure(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	// Issue SD-JWT with flat disclosure
	claims := map[string]any{
		"sub":          "user_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "john@example.com",
		"phone_number": "+1-202-555-0101",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"country":        "US",
		},
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "email", "phone_number", "address"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Create holder and present only name claims
	h := NewHolder(sdJWT)

	presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")
	presentation, err := h.PresentWithFrame(presFrame, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce-123",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Verify only 2 disclosures are included (given_name, family_name)
	if len(presentation.SDJWT.Disclosures) != 2 {
		t.Errorf("Expected 2 disclosures, got %d", len(presentation.SDJWT.Disclosures))
	}

	// Verify KB-JWT is present
	if presentation.KeyBindingJWT == "" {
		t.Error("Expected KB-JWT in presentation")
	}

	// Verify the disclosed claims are correct
	disclosedClaims := make(map[string]bool)
	for _, d := range presentation.SDJWT.Disclosures {
		disclosedClaims[d.ClaimName] = true
	}
	if !disclosedClaims["given_name"] || !disclosedClaims["family_name"] {
		t.Error("Expected given_name and family_name in disclosures")
	}
	if disclosedClaims["email"] || disclosedClaims["address"] {
		t.Error("email and address should not be in disclosures")
	}
}

// TestPresentWithFrameStructuredDisclosure tests presenting from a structured disclosure SD-JWT.
func TestPresentWithFrameStructuredDisclosure(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	// Issue SD-JWT with structured disclosure (nested address claims)
	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "CA",
			"country":        "US",
		},
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD: []string{"street_address", "locality", "region", "country"},
			},
		},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Create holder and present given_name and only locality from address
	h := NewHolder(sdJWT)

	presFrame := sdjwt.NewPresentationFrame("given_name").
		WithNested("address", sdjwt.NewPresentationFrame("locality"))

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Should have 2 disclosures: given_name and locality
	if len(presentation.SDJWT.Disclosures) != 2 {
		t.Errorf("Expected 2 disclosures, got %d", len(presentation.SDJWT.Disclosures))
	}

	// Verify correct disclosures
	claimNames := make(map[string]bool)
	for _, d := range presentation.SDJWT.Disclosures {
		claimNames[d.ClaimName] = true
	}
	if !claimNames["given_name"] {
		t.Error("Expected given_name in disclosures")
	}
	if !claimNames["locality"] {
		t.Error("Expected locality in disclosures")
	}
	if claimNames["street_address"] || claimNames["region"] || claimNames["country"] {
		t.Error("Unexpected address sub-claims in disclosures")
	}
}

// TestPresentWithFrameRecursiveDisclosure tests presenting from a recursive disclosure SD-JWT.
func TestPresentWithFrameRecursiveDisclosure(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	// Issue SD-JWT with recursive disclosure
	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"country":        "US",
		},
	}

	// address itself is SD, AND its sub-claims are also SD
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "address"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD: []string{"street_address", "locality", "country"},
			},
		},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Present address with only locality - should include address disclosure + locality
	h := NewHolder(sdJWT)

	presFrame := sdjwt.NewPresentationFrame().
		WithNested("address", sdjwt.NewPresentationFrame("locality"))

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Should include address (parent) and locality (child) disclosures
	if len(presentation.SDJWT.Disclosures) != 2 {
		t.Errorf("Expected 2 disclosures (address + locality), got %d", len(presentation.SDJWT.Disclosures))
	}
}

// TestPresentWithFrameArrayElements tests presenting from an array element disclosure SD-JWT.
func TestPresentWithFrameArrayElements(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	// Issue SD-JWT with array element disclosure
	claims := map[string]any{
		"sub":           "user_42",
		"nationalities": []any{"US", "DE", "FR"},
	}

	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"nationalities": {
				SD: []string{"0", "1", "2"},
			},
		},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Present only the first and third nationality
	h := NewHolder(sdJWT)

	presFrame := sdjwt.NewPresentationFrame().
		WithNested("nationalities", sdjwt.NewPresentationFrame("0", "2"))

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Should have 2 disclosures (elements 0 and 2)
	if len(presentation.SDJWT.Disclosures) != 2 {
		t.Errorf("Expected 2 disclosures, got %d", len(presentation.SDJWT.Disclosures))
	}

	// Verify values
	values := make(map[any]bool)
	for _, d := range presentation.SDJWT.Disclosures {
		values[d.ClaimValue] = true
	}
	if !values["US"] || !values["FR"] {
		t.Error("Expected US and FR in disclosures")
	}
	if values["DE"] {
		t.Error("DE should not be in disclosures")
	}
}

// TestPresentWithFrameNoKB tests presenting without key binding.
func TestPresentWithFrameNoKB(t *testing.T) {
	issuerSigner, _, _ := generateTestSigners(t)

	// Issue SD-JWT without holder binding
	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Create holder and present without KB
	h := NewHolder(sdJWT)

	presFrame := sdjwt.NewPresentationFrame("given_name")
	presentation, err := h.PresentWithFrameNoKB(presFrame)
	if err != nil {
		t.Fatalf("PresentWithFrameNoKB failed: %v", err)
	}

	// Verify disclosure is included
	if len(presentation.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(presentation.Disclosures))
	}
	if presentation.Disclosures[0].ClaimName != "given_name" {
		t.Errorf("Expected given_name disclosure, got %s", presentation.Disclosures[0].ClaimName)
	}
}

// TestPresentWithNilFrame tests presenting with nil frame (all disclosures).
func TestPresentWithNilFrame(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john@example.com",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "email"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)

	// Nil frame should include all disclosures
	presentation, err := h.PresentWithFrame(nil, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// All 3 disclosures should be included
	if len(presentation.SDJWT.Disclosures) != 3 {
		t.Errorf("Expected 3 disclosures, got %d", len(presentation.SDJWT.Disclosures))
	}
}

// TestGetPresentableKeys tests the GetPresentableKeys method.
func TestGetPresentableKeys(t *testing.T) {
	issuerSigner, _, _ := generateTestSigners(t)

	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
		"address": map[string]any{
			"street_address": "123 Main St",
			"locality":       "Anytown",
		},
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD: []string{"street_address"},
			},
		},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)
	keys, err := h.GetPresentableKeys()
	if err != nil {
		t.Fatalf("GetPresentableKeys failed: %v", err)
	}

	// Should have 3 presentable keys
	if len(keys) != 3 {
		t.Errorf("Expected 3 presentable keys, got %d: %v", len(keys), keys)
	}

	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}

	if !keyMap["given_name"] {
		t.Error("Expected given_name in presentable keys")
	}
	if !keyMap["family_name"] {
		t.Error("Expected family_name in presentable keys")
	}
	if !keyMap["address.street_address"] {
		t.Error("Expected address.street_address in presentable keys")
	}
}

// TestGetProcessedPayload tests the GetProcessedPayload method.
func TestGetProcessedPayload(t *testing.T) {
	issuerSigner, _, _ := generateTestSigners(t)

	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)
	processed, err := h.GetProcessedPayload()
	if err != nil {
		t.Fatalf("GetProcessedPayload failed: %v", err)
	}

	// Verify claims are in processed payload
	if processed.Claims["sub"] != "user_42" {
		t.Errorf("Expected sub=user_42, got %v", processed.Claims["sub"])
	}
	if processed.Claims["given_name"] != "John" {
		t.Errorf("Expected given_name=John, got %v", processed.Claims["given_name"])
	}
	if processed.Claims["family_name"] != "Doe" {
		t.Errorf("Expected family_name=Doe, got %v", processed.Claims["family_name"])
	}
}

// TestParseAndCreateHolder tests parsing a serialized SD-JWT.
func TestParseAndCreateHolder(t *testing.T) {
	issuerSigner, _, _ := generateTestSigners(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Serialize and parse back
	serialized := sdJWT.Serialize()

	h, err := ParseAndCreateHolder(serialized, issuerSigner, nil)
	if err != nil {
		t.Fatalf("ParseAndCreateHolder failed: %v", err)
	}

	// Verify holder has the disclosure
	if len(h.SDJWT.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(h.SDJWT.Disclosures))
	}
}

// TestKeyBindingJWTCreation tests that KB-JWT is created correctly.
func TestKeyBindingJWTCreation(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)

	kbOptions := KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "unique-nonce-12345",
	}

	presentation, err := h.PresentWithFrame(nil, holderSigner, kbOptions)
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Parse KB-JWT to verify claims
	kbParts := strings.Split(presentation.KeyBindingJWT, ".")
	if len(kbParts) != 3 {
		t.Fatal("KB-JWT should have 3 parts")
	}

	// Decode header
	headerBytes, _ := base64.RawURLEncoding.DecodeString(kbParts[0])
	var header map[string]any
	json.Unmarshal(headerBytes, &header)

	if header["typ"] != "kb+jwt" {
		t.Errorf("Expected typ=kb+jwt, got %v", header["typ"])
	}

	// Decode payload
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(kbParts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	if payload["aud"] != "https://verifier.example.org" {
		t.Errorf("Expected aud=https://verifier.example.org, got %v", payload["aud"])
	}
	if payload["nonce"] != "unique-nonce-12345" {
		t.Errorf("Expected nonce=unique-nonce-12345, got %v", payload["nonce"])
	}
	if _, ok := payload["sd_hash"].(string); !ok {
		t.Error("Expected sd_hash in KB-JWT")
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("Expected iat in KB-JWT")
	}
}

// TestPresentationSerialization tests that presentations serialize correctly.
func TestPresentationSerialization(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	claims := map[string]any{
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)

	presFrame := sdjwt.NewPresentationFrame("given_name")
	presentation, err := h.PresentWithFrame(presFrame, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Serialize
	serialized := SerializePresentation(presentation)

	// Should have: JWT~disclosure~KB-JWT (no trailing ~)
	parts := strings.Split(serialized, "~")
	// JWT has dots, disclosures don't, KB-JWT has dots
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts (JWT~disclosure~KB-JWT), got %d", len(parts))
	}

	// First part should be JWT (has dots)
	if !strings.Contains(parts[0], ".") {
		t.Error("First part should be JWT")
	}

	// Last part should be KB-JWT (has dots)
	if !strings.Contains(parts[2], ".") {
		t.Error("Last part should be KB-JWT")
	}
}

// TestComplexNestedPresentation tests presenting from a complex nested structure.
func TestComplexNestedPresentation(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	// Complex nested claims like OIDC IDA verified_claims
	claims := map[string]any{
		"sub": "user_42",
		"verified_claims": map[string]any{
			"verification": map[string]any{
				"trust_framework": "de_aml",
			},
			"claims": map[string]any{
				"given_name":  "Max",
				"family_name": "Mustermann",
				"birthdate":   "1956-01-28",
			},
		},
	}

	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"verified_claims": {
				Nested: map[string]*sdjwt.DisclosureFrame{
					"verification": {
						SD: []string{"trust_framework"},
					},
					"claims": {
						SD: []string{"given_name", "family_name", "birthdate"},
					},
				},
			},
		},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	// Present only given_name from verified_claims.claims
	h := NewHolder(sdJWT)

	presFrame := &sdjwt.PresentationFrame{
		Nested: map[string]*sdjwt.PresentationFrame{
			"verified_claims": {
				Nested: map[string]*sdjwt.PresentationFrame{
					"claims": {
						Include: map[string]bool{
							"given_name": true,
						},
					},
				},
			},
		},
	}

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	// Should have 1 disclosure (given_name)
	if len(presentation.SDJWT.Disclosures) != 1 {
		t.Errorf("Expected 1 disclosure, got %d", len(presentation.SDJWT.Disclosures))
	}
	if presentation.SDJWT.Disclosures[0].ClaimName != "given_name" {
		t.Errorf("Expected given_name, got %s", presentation.SDJWT.Disclosures[0].ClaimName)
	}
}

// TestGetHolderPublicKey tests extracting the holder public key from SD-JWT.
func TestGetHolderPublicKey(t *testing.T) {
	issuerSigner, _, holderPubJWK := generateTestSigners(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)
	pubKeyBytes, err := h.GetHolderPublicKey()
	if err != nil {
		t.Fatalf("GetHolderPublicKey failed: %v", err)
	}

	// Verify it's valid JSON
	var jwk map[string]any
	if err := json.Unmarshal(pubKeyBytes, &jwk); err != nil {
		t.Fatalf("Failed to parse JWK: %v", err)
	}

	if jwk["kty"] != "EC" {
		t.Errorf("Expected kty=EC, got %v", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("Expected crv=P-256, got %v", jwk["crv"])
	}
}

// TestVerifyIssuerSignature tests verifying the issuer signature.
func TestVerifyIssuerSignature(t *testing.T) {
	issuerSigner, _, _ := generateTestSigners(t)

	claims := map[string]any{
		"sub":        "user_42",
		"given_name": "John",
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"},
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := NewHolder(sdJWT)

	// Verify with correct public key
	err = h.VerifyIssuerSignature(issuerSigner)
	if err != nil {
		t.Errorf("VerifyIssuerSignature failed with correct key: %v", err)
	}

	// Verify with wrong public key
	wrongSigner, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to create wrong signer: %v", err)
	}
	err = h.VerifyIssuerSignature(wrongSigner)
	if err == nil {
		t.Error("VerifyIssuerSignature should fail with wrong key")
	}
}

// Helper functions

func generateTestSigners(t *testing.T) (signer.Signer, signer.Signer, []byte) {
	t.Helper()

	issuerSigner, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to generate issuer signer: %v", err)
	}

	holderSigner, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to generate holder signer: %v", err)
	}

	holderPub, ok := holderSigner.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("holder signer public key is not ECDSA")
	}

	return issuerSigner, holderSigner, ecdsaToJWK(holderPub)
}

func ecdsaToJWK(pub *ecdsa.PublicKey) []byte {
	curveName := ""
	switch pub.Curve {
	case elliptic.P256():
		curveName = "P-256"
	case elliptic.P384():
		curveName = "P-384"
	case elliptic.P521():
		curveName = "P-521"
	}

	byteSize := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	xPadded := make([]byte, byteSize)
	yPadded := make([]byte, byteSize)
	copy(xPadded[byteSize-len(xBytes):], xBytes)
	copy(yPadded[byteSize-len(yBytes):], yBytes)

	jwk := map[string]string{
		"kty": "EC",
		"crv": curveName,
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	data, _ := json.Marshal(jwk)
	return data
}
