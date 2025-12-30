package main

import (
	"encoding/json"
	"fmt"

	"github.com/georgepadayatti/sdjwt/sdjwtvc"
)

// demoVCTMetadata demonstrates VCT metadata structures
func demoVCTMetadata() {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 7: VCT Metadata Structures                                 │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	// Create comprehensive VCT metadata
	metadata := sdjwtvc.VCTMetadata{
		VCT:              "https://example.com/credentials/IdentityCredential",
		Name:             "Identity Credential",
		Description:      "A credential for identity verification",
		Extends:          []string{"https://example.com/credentials/BaseCredential"},
		ExtendsIntegrity: []string{"sha256-base123"},
		Schema:           "https://example.com/schemas/identity.json",
		SchemaIntegrity:  "sha256-schema456",
		Display: []sdjwtvc.DisplayMetadata{
			{
				Locale:      "en-US",
				Name:        "Identity Credential",
				Description: "Verify your identity securely",
				Rendering: &sdjwtvc.RenderingMetadata{
					Simple: &sdjwtvc.SimpleRendering{
						Logo: &sdjwtvc.LogoMetadata{
							URI:          "https://example.com/logo.png",
							URIIntegrity: "sha256-logo789",
							AltText:      "Example Corp Logo",
						},
						BackgroundImage: &sdjwtvc.BackgroundImageMetadata{
							URI:          "https://example.com/background.png",
							URIIntegrity: "sha256-bg012",
						},
						BackgroundColor: "#1E90FF",
						TextColor:       "#FFFFFF",
					},
					SVGTemplates: []sdjwtvc.SVGTemplate{
						{
							URI:          "https://example.com/card.svg",
							URIIntegrity: "sha256-svg012",
						},
					},
				},
			},
			{
				Locale:      "de-DE",
				Name:        "Identitätsnachweis",
				Description: "Verifizieren Sie Ihre Identität sicher",
			},
		},
		Claims: []sdjwtvc.ClaimMetadata{
			{
				Path:      sdjwtvc.NewClaimPath("given_name"),
				Mandatory: true,
				SD:        sdjwtvc.SDAlways,
				SVGID:     "given_name_field",
				Display: []sdjwtvc.DisplayMetadata{
					{Locale: "en-US", Label: "First Name"},
					{Locale: "de-DE", Label: "Vorname"},
				},
			},
			{
				Path:      sdjwtvc.NewClaimPath("family_name"),
				Mandatory: true,
				SD:        sdjwtvc.SDAlways,
			},
			{
				Path: sdjwtvc.NewClaimPath("address", "street"),
				SD:   sdjwtvc.SDAllowed,
			},
			{
				Path: sdjwtvc.NewClaimPath("address", "country"),
				SD:   sdjwtvc.SDNever,
			},
			{
				Path: sdjwtvc.NewClaimPath("nationalities", nil), // Wildcard
				SD:   sdjwtvc.SDAlways,
			},
		},
	}

	fmt.Printf("  VCT: %s\n", metadata.VCT)
	fmt.Printf("  Name: %s\n", metadata.Name)
	fmt.Printf("  Display locales: %d\n", len(metadata.Display))
	fmt.Printf("  Claims defined: %d\n", len(metadata.Claims))

	fmt.Println("\n  Claim Paths:")
	for _, claim := range metadata.Claims {
		fmt.Printf("    %s (SD: %s, Mandatory: %v)\n",
			claim.Path.String(), claim.SD, claim.Mandatory)
	}

	// Serialize metadata to JSON
	metadataJSON, _ := json.MarshalIndent(metadata, "  ", "    ")
	fmt.Printf("\n  Metadata JSON (truncated):\n  %s...\n", string(metadataJSON)[:200])
}
