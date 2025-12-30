package main

import (
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/holder"
	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// demoNestedClaims demonstrates SD-JWT with nested object claims
func demoNestedClaims(issuerSigner signer.Signer, holderSigner signer.Signer, holderPubJWK []byte) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 2: Nested Claims with Selective Disclosure                 │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	iss := issuer.NewIssuer(issuerSigner)

	claims := map[string]any{
		"iss": "https://issuer.example.com",
		"iat": time.Now().Unix(),
		"sub": "user_42",
		"address": map[string]any{
			"street_address": "123 Main Street",
			"locality":       "Anytown",
			"region":         "CA",
			"country":        "US",
		},
	}

	// Make address.street_address and address.locality selectively disclosable
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"address": {
				SD: []string{"street_address", "locality"},
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})
	if err != nil {
		log.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	fmt.Printf("  SD-JWT created with %d disclosures (nested claims)\n", len(sdJWT.Disclosures))
	for i, d := range sdJWT.Disclosures {
		fmt.Printf("    Disclosure %d: %s = %v\n", i+1, d.ClaimName, d.ClaimValue)
	}
	serialized := sdJWT.Serialize()
	fmt.Printf("  [DEBUG] SD-JWT Token (compact, nested):\n%s\n", serialized)

	// Holder creates presentation with only street_address using frame-based API
	h := holder.NewHolder(sdJWT)
	presFrame := sdjwt.NewPresentationFrame().WithNested("address", sdjwt.NewPresentationFrame("street_address"))
	presentation, _ := h.PresentWithFrame(
		presFrame,
		holderSigner,
		holder.KeyBindingOptions{Audience: "https://verifier.example.org", Nonce: "nonce123"},
	)

	fmt.Printf("  Presentation created with %d disclosure(s)\n", len(presentation.SDJWT.Disclosures))
	presentationSerialized := holder.SerializePresentation(presentation)
	fmt.Printf("  [DEBUG] SD-JWT Presentation Token (compact, nested):\n%s\n", presentationSerialized)
}
