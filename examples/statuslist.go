package main

import (
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/sdjwtvc"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/statuslist"
)

// demoStatusList demonstrates credential revocation with status lists
func demoStatusList(issuerSigner signer.Signer) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 6: Status List (Credential Revocation)                     │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	// Create a status list with 10000 entries
	sl, err := statuslist.NewStatusList(10000, statuslist.Bits1)
	if err != nil {
		log.Fatalf("Failed to create status list: %v", err)
	}

	fmt.Printf("  Created status list with %d entries\n", 10000)

	// Revoke some credentials
	sl.SetStatus(42, statuslist.StatusInvalid)
	sl.SetStatus(100, statuslist.StatusInvalid)
	sl.SetStatus(999, statuslist.StatusInvalid)

	fmt.Println("  Revoked credentials at indices: 42, 100, 999")

	// Check statuses
	testIndices := []int{41, 42, 43, 100, 500}
	for _, idx := range testIndices {
		status, _ := sl.GetStatus(idx)
		statusStr := "VALID"
		if status == statuslist.StatusInvalid {
			statusStr = "REVOKED"
		}
		fmt.Printf("    Index %d: %s\n", idx, statusStr)
	}

	// Create status list token
	token, _ := statuslist.NewStatusListToken(
		"https://issuer.example.com",
		"https://issuer.example.com/status/1",
		sl,
		time.Now().Unix(),
		time.Now().Add(24*time.Hour).Unix(),
	)

	// Serialize the token to JSON
	tokenJSON, _ := token.ToJSON()
	fmt.Printf("\n  Status List Token created (%d bytes)\n", len(tokenJSON))

	// Sign the status list token
	signedToken, err := token.Sign(issuerSigner, &statuslist.StatusListSignOptions{
		Type: "statuslist+jwt",
	})
	if err != nil {
		log.Fatalf("Failed to sign status list token: %v", err)
	}
	fmt.Printf("  Signed Status List Token length: %d bytes\n", len(signedToken))

	// Demonstrate checking VC status
	vcPayload := map[string]any{
		"vct": "https://example.com/credentials/IdentityCredential",
		"status": map[string]any{
			"status_list": map[string]any{
				"idx": 42,
				"uri": "https://issuer.example.com/status/1",
			},
		},
	}

	valid, _ := sdjwtvc.CheckStatus(vcPayload, token, 10000)
	fmt.Printf("  VC at index 42 is valid: %v (expected: false - revoked)\n", valid)

	vcPayload["status"].(map[string]any)["status_list"].(map[string]any)["idx"] = 500
	valid, _ = sdjwtvc.CheckStatus(vcPayload, token, 10000)
	fmt.Printf("  VC at index 500 is valid: %v (expected: true)\n", valid)
}
