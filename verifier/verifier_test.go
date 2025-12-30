package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/georgepadayatti/sdjwt/holder"
	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// TestVerifyFlatDisclosure tests verifying an SD-JWT with flat disclosure.
func TestVerifyFlatDisclosure(t *testing.T) {
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

	// Create presentation with some claims
	h := holder.NewHolder(sdJWT)
	presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")
	presentation, err := h.PresentWithFrame(presFrame, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce-123",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	// Verify with required claims and key binding
	v := NewVerifier(issuerSigner)
	requiredClaims := sdjwt.NewPresentationFrame("given_name", "family_name")
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce-123",
		Audience: "https://verifier.example.org",
		MaxAge:   300,
	}

	result, err := v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true, got false. Errors: %v", result.Errors)
	}
	if result.KeyBindingValid == nil || !*result.KeyBindingValid {
		t.Error("Expected KeyBindingValid=true")
	}
	if len(result.MissingRequired) > 0 {
		t.Errorf("Expected no missing required claims, got %v", result.MissingRequired)
	}
}

// TestVerifyStructuredDisclosure tests verifying an SD-JWT with structured disclosure.
func TestVerifyStructuredDisclosure(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

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

	h := holder.NewHolder(sdJWT)
	presFrame := sdjwt.NewPresentationFrame("given_name").
		WithNested("address", sdjwt.NewPresentationFrame("locality"))

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	requiredClaims := sdjwt.NewPresentationFrame("given_name")
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	result, err := v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true, got false. Errors: %v", result.Errors)
	}

	// Verify disclosed claims
	foundGivenName := false
	foundLocality := false
	for _, c := range result.DisclosedClaims {
		if c == "given_name" {
			foundGivenName = true
		}
		if c == "address.locality" {
			foundLocality = true
		}
	}
	if !foundGivenName {
		t.Error("Expected given_name in disclosed claims")
	}
	if !foundLocality {
		t.Error("Expected address.locality in disclosed claims")
	}
}

// TestVerifyArrayElementDisclosure tests verifying an SD-JWT with array element disclosure.
func TestVerifyArrayElementDisclosure(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

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

	h := holder.NewHolder(sdJWT)
	presFrame := sdjwt.NewPresentationFrame().
		WithNested("nationalities", sdjwt.NewPresentationFrame("0", "2"))

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true, got false. Errors: %v", result.Errors)
	}

	// Verify the nationalities array in processed payload
	natArr, ok := result.ProcessedPayload["nationalities"].([]any)
	if !ok {
		t.Fatal("Expected nationalities array in processed payload")
	}
	// Should have US and FR (indices 0 and 2), not DE
	if len(natArr) != 2 {
		t.Errorf("Expected 2 nationalities, got %d", len(natArr))
	}
}

// TestVerifyWithoutKeyBinding tests verifying an SD-JWT without key binding.
func TestVerifyWithoutKeyBinding(t *testing.T) {
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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrameNoKB(nil)
	if err != nil {
		t.Fatalf("PresentWithFrameNoKB failed: %v", err)
	}

	serialized := presentation.Serialize()

	v := NewVerifier(issuerSigner)
	requiredClaims := sdjwt.NewPresentationFrame("given_name")
	result, err := v.Verify(serialized, requiredClaims)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true, got false. Errors: %v", result.Errors)
	}
	if result.ProcessedPayload["given_name"] != "John" {
		t.Errorf("Expected given_name=John, got %v", result.ProcessedPayload["given_name"])
	}
}

// TestVerifyMissingRequiredClaims tests that verification fails when required claims are missing.
func TestVerifyMissingRequiredClaims(t *testing.T) {
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

	// Present only given_name, but require email too
	h := holder.NewHolder(sdJWT)
	presFrame := sdjwt.NewPresentationFrame("given_name")
	presentation, err := h.PresentWithFrame(presFrame, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	requiredClaims := sdjwt.NewPresentationFrame("given_name", "email") // email is not disclosed
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	result, err := v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	// Should be invalid due to missing required claim
	if result.Valid {
		t.Error("Expected Valid=false due to missing required claim")
	}
	if len(result.MissingRequired) != 1 || result.MissingRequired[0] != "email" {
		t.Errorf("Expected MissingRequired=[email], got %v", result.MissingRequired)
	}
}

// TestVerifyInvalidIssuerSignature tests that verification fails with wrong issuer key.
func TestVerifyInvalidIssuerSignature(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)
	wrongSigner, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to generate wrong signer: %v", err)
	}

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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	// Verify with wrong issuer key
	v := NewVerifier(wrongSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	_, err = v.VerifyWithKeyBinding(serialized, nil, keyBinding)
	if err == nil {
		t.Error("Expected verification to fail with wrong issuer key")
	}
}

// TestVerifyInvalidKBJWTNonce tests that verification fails with wrong nonce.
func TestVerifyInvalidKBJWTNonce(t *testing.T) {
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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "correct-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "wrong-nonce", // Different nonce
		Audience: "https://verifier.example.org",
	}

	result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)

	// Verification should complete but KB should be invalid
	if err != nil {
		// It's acceptable if it returns an error for nonce mismatch
		return
	}

	if result.KeyBindingValid != nil && *result.KeyBindingValid {
		t.Error("Expected KeyBindingValid=false due to nonce mismatch")
	}
}

// TestVerifyInvalidKBJWTAudience tests that verification fails with wrong audience.
func TestVerifyInvalidKBJWTAudience(t *testing.T) {
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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
		Audience: "https://correct-verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://wrong-verifier.example.org", // Different audience
	}

	result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)

	if err != nil {
		// Acceptable if error is returned
		return
	}

	if result.KeyBindingValid != nil && *result.KeyBindingValid {
		t.Error("Expected KeyBindingValid=false due to audience mismatch")
	}
}

// TestVerifyKBJWTMaxAge tests that verification fails when KB-JWT is too old.
func TestVerifyKBJWTMaxAge(t *testing.T) {
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

	h := holder.NewHolder(sdJWT)
	// Create presentation with old IssuedAt
	presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
		IssuedAt: time.Now().Add(-10 * time.Minute), // 10 minutes ago
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
		MaxAge:   60, // Only 60 seconds allowed
	}

	result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)

	if err != nil {
		// Acceptable if error is returned
		return
	}

	if result.KeyBindingValid != nil && *result.KeyBindingValid {
		t.Error("Expected KeyBindingValid=false due to KB-JWT being too old")
	}
}

// TestVerifyMissingKeyBindingWhenRequired tests that verification fails when KB is required but missing.
func TestVerifyMissingKeyBindingWhenRequired(t *testing.T) {
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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrameNoKB(nil)
	if err != nil {
		t.Fatalf("PresentWithFrameNoKB failed: %v", err)
	}

	serialized := presentation.Serialize()

	v := NewVerifier(issuerSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	_, err = v.VerifyWithKeyBinding(serialized, nil, keyBinding)

	if err == nil {
		t.Error("Expected error when KB is required but missing")
	}
}

// TestVerifyRequiredClaimInPayload tests that non-SD claims satisfy required claim check.
func TestVerifyRequiredClaimInPayload(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	claims := map[string]any{
		"sub":        "user_42", // Not SD - always visible
		"given_name": "John",    // SD
	}

	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name"}, // Only given_name is SD
	}

	iss := issuer.NewIssuer(issuerSigner)
	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		t.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	requiredClaims := sdjwt.NewPresentationFrame("sub") // sub is in payload, not disclosed
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	result, err := v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true, got false. Errors: %v, MissingRequired: %v", result.Errors, result.MissingRequired)
	}
	if len(result.MissingRequired) > 0 {
		t.Errorf("sub should not be missing (it's in payload), got %v", result.MissingRequired)
	}
}

// TestVerifyTrustedIssuers tests issuer validation with trusted issuers list.
func TestVerifyTrustedIssuers(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

	claims := map[string]any{
		"iss":        "https://trusted-issuer.example.com",
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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	// Test with trusted issuer
	v := NewVerifier(issuerSigner)
	v.TrustedIssuers = []string{"https://trusted-issuer.example.com"}

	result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true with trusted issuer, got false. Errors: %v", result.Errors)
	}

	// Test with untrusted issuer
	v.TrustedIssuers = []string{"https://other-issuer.example.com"}
	_, err = v.VerifyWithKeyBinding(serialized, nil, keyBinding)
	if err == nil {
		t.Error("Expected error with untrusted issuer")
	}
}

// TestVerifyHashAlgorithms tests verification with different hash algorithms.
func TestVerifyHashAlgorithms(t *testing.T) {
	algorithms := []string{"sha-256", "sha-384", "sha-512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
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
				HashAlgorithm:   alg,
			})
			if err != nil {
				t.Fatalf("Failed to issue SD-JWT: %v", err)
			}

			h := holder.NewHolder(sdJWT)
			presentation, err := h.PresentWithFrame(nil, holderSigner, holder.KeyBindingOptions{
				Audience: "https://verifier.example.org",
				Nonce:    "test-nonce",
			})
			if err != nil {
				t.Fatalf("PresentWithFrame failed: %v", err)
			}

			serialized := holder.SerializePresentation(presentation)

			v := NewVerifier(issuerSigner)
			keyBinding := &KeyBindingRequirement{
				Nonce:    "test-nonce",
				Audience: "https://verifier.example.org",
			}

			result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)
			if err != nil {
				t.Fatalf("VerifyWithKeyBinding failed: %v", err)
			}

			if !result.Valid {
				t.Errorf("Expected Valid=true for %s, got false. Errors: %v", alg, result.Errors)
			}
		})
	}
}

// TestVerifyProcessedPayload tests that processed payload contains correct values.
func TestVerifyProcessedPayload(t *testing.T) {
	issuerSigner, holderSigner, holderPubJWK := generateTestSigners(t)

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
				SD: []string{"street_address", "locality"},
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

	h := holder.NewHolder(sdJWT)
	presFrame := sdjwt.NewPresentationFrame("given_name").
		WithNested("address", sdjwt.NewPresentationFrame("locality"))

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "test-nonce",
	})
	if err != nil {
		t.Fatalf("PresentWithFrame failed: %v", err)
	}

	serialized := holder.SerializePresentation(presentation)

	v := NewVerifier(issuerSigner)
	keyBinding := &KeyBindingRequirement{
		Nonce:    "test-nonce",
		Audience: "https://verifier.example.org",
	}

	result, err := v.VerifyWithKeyBinding(serialized, nil, keyBinding)
	if err != nil {
		t.Fatalf("VerifyWithKeyBinding failed: %v", err)
	}

	// Check processed payload
	if result.ProcessedPayload["sub"] != "user_42" {
		t.Errorf("Expected sub=user_42, got %v", result.ProcessedPayload["sub"])
	}
	if result.ProcessedPayload["given_name"] != "John" {
		t.Errorf("Expected given_name=John, got %v", result.ProcessedPayload["given_name"])
	}
	// family_name should NOT be in processed payload (not disclosed)
	if _, exists := result.ProcessedPayload["family_name"]; exists {
		t.Error("family_name should not be in processed payload")
	}

	// Check nested address
	address, ok := result.ProcessedPayload["address"].(map[string]any)
	if !ok {
		t.Fatal("Expected address in processed payload")
	}
	if address["locality"] != "Anytown" {
		t.Errorf("Expected locality=Anytown, got %v", address["locality"])
	}
	// street_address should NOT be in address (not disclosed)
	if _, exists := address["street_address"]; exists {
		t.Error("street_address should not be in address")
	}
}

// TestVerifySDJWTString tests the convenience function.
func TestVerifySDJWTString(t *testing.T) {
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

	h := holder.NewHolder(sdJWT)
	presentation, err := h.PresentWithFrameNoKB(nil)
	if err != nil {
		t.Fatalf("PresentWithFrameNoKB failed: %v", err)
	}

	serialized := presentation.Serialize()

	// Use convenience function
	requiredClaims := sdjwt.NewPresentationFrame("given_name")
	result, err := VerifySDJWTString(serialized, issuerSigner, requiredClaims)
	if err != nil {
		t.Fatalf("VerifySDJWTString failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected Valid=true, got false. Errors: %v", result.Errors)
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
