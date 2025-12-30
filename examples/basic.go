package main

import (
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/holder"
	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/verifier"
)

// demoBasicSDJWT demonstrates basic SD-JWT issuance, presentation, and verification
func demoBasicSDJWT(issuerSigner signer.Signer, holderSigner signer.Signer, holderPubJWK []byte) {
	fmt.Println("┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 1: Basic SD-JWT Flow (Issue → Present → Verify)            │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	// === ISSUER ===
	fmt.Println("\n[ISSUER] Creating SD-JWT with selectively disclosable claims...")

	iss := issuer.NewIssuer(issuerSigner)

	claims := map[string]any{
		"iss":         "https://issuer.example.com",
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(365 * 24 * time.Hour).Unix(),
		"sub":         "user_42",
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john@example.com",
		"birthdate":   "1990-01-15",
	}

	// Create frame: given_name, family_name, email, birthdate are selectively disclosable
	frame := &sdjwt.DisclosureFrame{
		SD:      []string{"given_name", "family_name", "email", "birthdate"},
		SDDecoy: 2, // Add 2 decoy digests
	}

	opts := &issuer.IssueOptions{
		HashAlgorithm:   "sha-256",
		HolderPublicKey: holderPubJWK,
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, opts)
	if err != nil {
		log.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	serialized := sdJWT.Serialize()
	fmt.Printf("  SD-JWT created with %d disclosures\n", len(sdJWT.Disclosures))
	fmt.Printf("  Serialized length: %d bytes\n", len(serialized))
	fmt.Printf("  [DEBUG] SD-JWT Token (compact):\n%s\n", serialized)

	// === HOLDER ===
	fmt.Println("\n[HOLDER] Receiving and creating presentation...")

	h, err := holder.ParseAndCreateHolder(serialized, issuerSigner, nil)
	if err != nil {
		log.Fatalf("Failed to parse SD-JWT: %v", err)
	}

	// Get available keys that can be presented
	availableKeys, _ := h.GetPresentableKeys()
	fmt.Printf("  Available claims: %v\n", availableKeys)

	// Create presentation frame to select given_name and family_name
	presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")
	fmt.Printf("  Selecting claims for disclosure: [given_name family_name]\n")

	kbOptions := holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "abc123xyz",
	}

	presentation, err := h.PresentWithFrame(presFrame, holderSigner, kbOptions)
	if err != nil {
		log.Fatalf("Failed to create presentation: %v", err)
	}

	presentationSerialized := holder.SerializePresentation(presentation)
	fmt.Printf("  Presentation created with %d disclosures\n", len(presentation.SDJWT.Disclosures))
	fmt.Printf("  [DEBUG] SD-JWT Presentation Token (compact):\n%s\n", presentationSerialized)

	// === VERIFIER ===
	fmt.Println("\n[VERIFIER] Verifying presentation...")

	v := verifier.NewVerifier(issuerSigner)

	// Use presentation frame for required claims
	requiredClaims := sdjwt.NewPresentationFrame("given_name", "family_name")

	// Key binding requirement is provided to holder and used for verification
	keyBinding := &verifier.KeyBindingRequirement{
		Nonce:    "abc123xyz",
		Audience: "https://verifier.example.org",
		MaxAge:   300,
	}

	result, err := v.VerifyWithKeyBinding(presentationSerialized, requiredClaims, keyBinding)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	fmt.Printf("  Valid: %v\n", result.Valid)
	fmt.Printf("  Key Binding Valid: %v\n", *result.KeyBindingValid)
	fmt.Printf("  Disclosed Claims: %v\n", result.DisclosedClaims)
	fmt.Printf("  Missing Required: %v\n", result.MissingRequired)
}
