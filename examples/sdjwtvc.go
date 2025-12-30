package main

import (
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/holder"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/sdjwtvc"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/verifier"
)

// demoSDJWTVC demonstrates SD-JWT VC (Verifiable Credentials)
func demoSDJWTVC(issuerSigner signer.Signer, holderSigner signer.Signer, holderPubJWK []byte) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 5: SD-JWT VC (Verifiable Credentials) - draft-13           │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	// Create VC issuer
	vcIssuer, err := sdjwtvc.NewVCIssuer(sdjwtvc.IssuerConfig{
		IssuerID:      "https://issuer.example.com",
		Signer:        issuerSigner,
		HashAlgorithm: "sha-256",
	})
	if err != nil {
		log.Fatalf("Failed to create VC issuer: %v", err)
	}

	// Credential claims
	claims := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"birthdate":   "1990-01-15",
		"address": map[string]any{
			"street":  "123 Main St",
			"city":    "Anytown",
			"country": "US",
		},
	}

	// Disclosure frame
	frame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name", "birthdate"},
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {SD: []string{"street", "city"}},
		},
	}

	// Issue VC
	exp := time.Now().Add(365 * 24 * time.Hour)
	vc, err := vcIssuer.Issue(claims, frame, sdjwtvc.VCIssueOptions{
		VCT:             "https://example.com/credentials/IdentityCredential",
		VCTIntegrity:    "sha256-abc123",
		Subject:         "did:example:12345",
		ExpirationTime:  &exp,
		HolderPublicKey: holderPubJWK,
		Status: &sdjwtvc.StatusListReference{
			Index: 42,
			URI:   "https://issuer.example.com/status/1",
		},
		DecoyDigests: 2,
	})
	if err != nil {
		log.Fatalf("Failed to issue VC: %v", err)
	}

	fmt.Printf("  SD-JWT VC issued with %d disclosures\n", len(vc.Disclosures))
	fmt.Printf("  Media Type: %s\n", sdjwtvc.MediaType)
	fmt.Printf("  Type Header: %s\n", sdjwtvc.TypeHeader)
	vcSerialized := vc.Serialize()
	fmt.Printf("  [DEBUG] SD-JWT VC Token (compact):\n%s\n", vcSerialized)

	// Demonstrate selective disclosure rules
	fmt.Println("\n  Selective Disclosure Rules (per Section 3.2.2.2):")
	testClaims := []string{"vct", "iss", "exp", "sub", "iat", "given_name"}
	for _, claim := range testClaims {
		canSD := sdjwtvc.IsClaimSelectivelyDisclosable(claim)
		mustNot := sdjwtvc.MustNotBeSelectivelyDisclosed(claim)
		fmt.Printf("    %s: canSD=%v, mustNotSD=%v\n", claim, canSD, mustNot)
	}

	// Create holder presentation using frame-based API
	h := holder.NewHolder(vc)
	presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")
	presentation, _ := h.PresentWithFrame(
		presFrame,
		holderSigner,
		holder.KeyBindingOptions{
			Audience: "https://verifier.example.org",
			Nonce:    "vc-nonce-123",
		},
	)

	vcPresentationSerialized := holder.SerializePresentation(presentation)
	fmt.Printf("  [DEBUG] SD-JWT VC Presentation Token (compact):\n%s\n", vcPresentationSerialized)

	// Verify
	vcRequiredClaims := sdjwt.NewPresentationFrame("given_name")
	vcKeyBinding := &verifier.KeyBindingRequirement{
		Nonce:    "vc-nonce-123",
		Audience: "https://verifier.example.org",
	}
	result, _ := sdjwtvc.VerifySDJWTVCWithKeyBinding(
		vcPresentationSerialized,
		issuerSigner,
		vcRequiredClaims,
		vcKeyBinding,
		&sdjwtvc.VCVerificationOptions{
			Validation: &sdjwtvc.ValidationOptions{
				SkipExpirationCheck: false,
			},
		},
	)

	fmt.Printf("\n  VC Verification: Valid=%v, KB Valid=%v\n", result.Valid, *result.KeyBindingValid)
}
