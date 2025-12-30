package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/holder"
	"github.com/georgepadayatti/sdjwt/issuer"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/sdjwtvc"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/verifier"
	"github.com/golang-jwt/jwt/v5"
)

// MockHSMSigner demonstrates a custom signer implementation
// In production, this would integrate with an actual HSM or cloud KMS
type MockHSMSigner struct {
	key       *ecdsa.PrivateKey
	algorithm string
	signCount int
}

func (s *MockHSMSigner) Sign(signingInput string) ([]byte, error) {
	s.signCount++
	// In production, this would call the HSM/KMS API
	return jwt.SigningMethodES256.Sign(signingInput, s.key)
}

func (s *MockHSMSigner) Algorithm() string {
	return s.algorithm
}

func (s *MockHSMSigner) PublicKey() crypto.PublicKey {
	if s.key == nil {
		return nil
	}
	return &s.key.PublicKey
}

func (s *MockHSMSigner) Certificate() *x509.Certificate {
	return nil
}

func (s *MockHSMSigner) CertificateChain() []*x509.Certificate {
	return nil
}

// demoCustomSigner demonstrates using custom signer interface for HSM/KMS integration
func demoCustomSigner(issuerSigner signer.Signer, holderSigner signer.Signer, holderPubJWK []byte) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 8: Custom Signer Interface (HSM/KMS Integration)           │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	if holderSigner != nil {
		fmt.Printf("\n  Default holder signer algorithm: %s\n", holderSigner.Algorithm())
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate mock issuer key: %v", err)
	}

	// Create a mock HSM signer (simulates external signing service)
	hsmSigner := &MockHSMSigner{
		key:       issuerKey,
		algorithm: "ES256",
	}
	fmt.Println("\n  Created MockHSMSigner (simulates HSM/KMS)")

	// === Method 1: Use with issuer.NewIssuer ===
	fmt.Println("\n  [Method 1] Using issuer.NewIssuer:")
	iss := issuer.NewIssuer(hsmSigner)

	claims := map[string]any{
		"iss":         "https://hsm-issuer.example.com",
		"iat":         time.Now().Unix(),
		"sub":         "hsm_user_1",
		"given_name":  "Alice",
		"family_name": "Smith",
	}

	frame := sdjwt.NewDisclosureFrame("given_name", "family_name")
	sdJWT, err := iss.IssueWithFrame(claims, frame, nil)
	if err != nil {
		log.Fatalf("Failed to issue SD-JWT with custom signer: %v", err)
	}

	serialized := sdJWT.Serialize()
	fmt.Printf("    SD-JWT issued with %d disclosures\n", len(sdJWT.Disclosures))
	fmt.Printf("    HSM sign operations: %d\n", hsmSigner.signCount)
	fmt.Printf("    [DEBUG] SD-JWT Token:\n%s\n", serialized)

	// Verify the SD-JWT (proves the custom signer worked correctly)
	v := verifier.NewVerifier(hsmSigner)
	result, _ := v.Verify(serialized, nil)
	fmt.Printf("    Verification: Valid=%v\n", result.Valid)

	// === Method 2: Use with holder for Key Binding JWT ===
	fmt.Println("\n  [Method 2] Using holder.CreateKeyBindingJWT:")
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate mock holder key: %v", err)
	}
	mockHolderSigner := &MockHSMSigner{
		key:       holderKey,
		algorithm: "ES256",
	}

	// First create an SD-JWT with holder key binding enabled
	issWithCnf := issuer.NewIssuer(issuerSigner)
	sdJWTWithCnf, _ := issWithCnf.IssueWithFrame(claims, frame, &issuer.IssueOptions{
		HolderPublicKey: holderPubJWK,
	})

	// Create KB-JWT using custom signer
	kbOptions := holder.KeyBindingOptions{
		Audience: "https://verifier.example.org",
		Nonce:    "custom-signer-nonce",
	}
	kbJWT, err := holder.CreateKeyBindingJWT(sdJWTWithCnf, mockHolderSigner, kbOptions)
	if err != nil {
		log.Fatalf("Failed to create KB-JWT with custom signer: %v", err)
	}
	fmt.Printf("    KB-JWT created using custom signer\n")
	fmt.Printf("    Holder HSM sign operations: %d\n", mockHolderSigner.signCount)
	fmt.Printf("    [DEBUG] KB-JWT:\n%s\n", kbJWT)

	// === Method 3: Use with sdjwtvc.NewVCIssuerWithSigner ===
	fmt.Println("\n  [Method 3] Using sdjwtvc.NewVCIssuerWithSigner:")
	vcSigner := &MockHSMSigner{
		key:       issuerKey,
		algorithm: "ES256",
	}

	vcIssuer, err := sdjwtvc.NewVCIssuerWithSigner("https://hsm-issuer.example.com", vcSigner, "sha-256")
	if err != nil {
		log.Fatalf("Failed to create VC issuer with custom signer: %v", err)
	}

	vcClaims := map[string]any{
		"given_name":  "Bob",
		"family_name": "Jones",
	}
	vcFrame := &sdjwt.DisclosureFrame{
		SD: []string{"given_name", "family_name"},
	}

	exp := time.Now().Add(365 * 24 * time.Hour)
	vc, err := vcIssuer.Issue(vcClaims, vcFrame, sdjwtvc.VCIssueOptions{
		VCT:            "https://example.com/credentials/IdentityCredential",
		Subject:        "did:example:hsm-user",
		ExpirationTime: &exp,
	})
	if err != nil {
		log.Fatalf("Failed to issue VC with custom signer: %v", err)
	}

	vcSerialized := vc.Serialize()
	fmt.Printf("    SD-JWT VC issued with %d disclosures\n", len(vc.Disclosures))
	fmt.Printf("    VC HSM sign operations: %d\n", vcSigner.signCount)
	fmt.Printf("    [DEBUG] SD-JWT VC Token:\n%s\n", vcSerialized)

	// === Method 4: Use DefaultSigner directly ===
	fmt.Println("\n  [Method 4] Using signer.NewDefaultSigner (local key):")
	defaultSigner, err := signer.NewDefaultSigner()
	if err != nil {
		log.Fatalf("Failed to create default signer: %v", err)
	}
	fmt.Printf("    Algorithm: %s\n", defaultSigner.Algorithm())

	issWithDefault := issuer.NewIssuer(defaultSigner)
	sdJWTDefault, _ := issWithDefault.IssueWithFrame(claims, frame, nil)
	fmt.Printf("    SD-JWT issued: %d disclosures\n", len(sdJWTDefault.Disclosures))

	fmt.Println("\n  Custom signer integration complete!")
	fmt.Println("  In production, replace MockHSMSigner with your HSM/KMS client.")
}
