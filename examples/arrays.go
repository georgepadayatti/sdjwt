package main

import (
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// demoArrayElements demonstrates SD-JWT with array element disclosure
func demoArrayElements(issuerSigner signer.Signer) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 3: Array Element Selective Disclosure                      │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	iss := issuer.NewIssuer(issuerSigner)

	claims := map[string]any{
		"iss":           "https://issuer.example.com",
		"iat":           time.Now().Unix(),
		"nationalities": []any{"US", "DE", "FR"},
	}

	// Make individual array elements selectively disclosable
	frame := &sdjwt.DisclosureFrame{
		Nested: map[string]*sdjwt.DisclosureFrame{
			"nationalities": {
				SD: []string{"0", "1", "2"}, // All array indices as strings
			},
		},
	}

	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		log.Fatalf("Failed to issue SD-JWT: %v", err)
	}

	fmt.Printf("  SD-JWT created with %d disclosures (array elements)\n", len(sdJWT.Disclosures))
	for i, d := range sdJWT.Disclosures {
		fmt.Printf("    Disclosure %d (array element): %v\n", i+1, d.ClaimValue)
	}
	serialized := sdJWT.Serialize()
	fmt.Printf("  [DEBUG] SD-JWT Token (compact, array elements):\n%s\n", serialized)
}
