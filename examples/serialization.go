package main

import (
	"fmt"

	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// demoJSONSerialization demonstrates different serialization formats
func demoJSONSerialization(issuerSigner signer.Signer) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 4: Serialization Formats (Compact, Flatten, General JSON)  │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	iss := issuer.NewIssuer(issuerSigner)

	claims := map[string]any{
		"name":  "Alice",
		"email": "alice@example.com",
	}

	frame := sdjwt.NewDisclosureFrame("name", "email")
	sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)

	// Compact serialization
	compact := sdJWT.Serialize()
	fmt.Printf("  Compact serialization: %d bytes\n", len(compact))
	fmt.Printf("  [DEBUG] SD-JWT Token (compact, serialization):\n%s\n", compact)

	// Flattened JSON serialization
	flatJSON, _ := sdJWT.SerializeFlattenJSON()
	fmt.Printf("  Flattened JSON: %d bytes\n", len(flatJSON))
	fmt.Printf("  [DEBUG] SD-JWT Token (flattened JSON):\n%s\n", flatJSON)

	// General JSON serialization
	generalJSON, _ := sdJWT.SerializeGeneralJSON()
	fmt.Printf("  General JSON: %d bytes\n", len(generalJSON))
	fmt.Printf("  [DEBUG] SD-JWT Token (general JSON):\n%s\n", generalJSON)

	// Parse back from JSON
	parsed, _, _ := sdjwt.ParseFlattenJSON(flatJSON, "sha-256")
	fmt.Printf("  Parsed from Flattened JSON: %d disclosures\n", len(parsed.Disclosures))
}
