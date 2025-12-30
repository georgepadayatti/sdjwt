package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"github.com/georgepadayatti/sdjwt/holder"
	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/sdjwtvc"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/verifier"
	"github.com/golang-jwt/jwt/v5"
)

// demoETSIEAA demonstrates ETSI TS 119 472-1 Electronic Attestation of Attributes
func demoETSIEAA(issuerSigner signer.Signer, holderSigner signer.Signer, holderPubJWK []byte) {
	fmt.Println("\n┌──────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ Demo 9: ETSI TS 119 472-1 EAA (Electronic Attestation)          │")
	fmt.Println("└──────────────────────────────────────────────────────────────────┘")

	cert := issuerSigner.Certificate()
	if cert == nil {
		log.Fatalf("Issuer signer does not provide a signing certificate")
	}
	chain := issuerSigner.CertificateChain()
	if len(chain) == 0 {
		chain = []*x509.Certificate{cert}
	}
	fmt.Println("\n  Generated self-signed X.509 certificate for issuer")

	// === QEAA (Qualified EAA) Issuer ===
	fmt.Println("\n  [QEAA] Creating Qualified EAA Issuer...")

	qeaaIssuer, err := sdjwtvc.NewEAAIssuer(sdjwtvc.EAAIssuerConfig{
		Category:                sdjwtvc.EAACategoryQEAA,
		IssuerID:                "https://qualified-issuer.example.eu",
		IssuingAuthority:        "German Federal Authority for Digital Identity",
		IssuingCountry:          "DE",
		IssuerRegistrationID:    "NTDE-HRB12345",
		Signer:                  issuerSigner,
		SigningCertificate:      cert,
		SigningCertificateChain: chain,
		SigningCertificateURL:   "https://qualified-issuer.example.eu/certs/signing.pem",
	})
	if err != nil {
		log.Fatalf("Failed to create QEAA issuer: %v", err)
	}

	fmt.Printf("    Category: QEAA (%s)\n", sdjwtvc.CategoryQEAA)
	fmt.Printf("    Issuing Authority: German Federal Authority for Digital Identity\n")
	fmt.Printf("    Issuing Country: DE\n")

	// Define identity claims for a German citizen
	claims := map[string]any{
		"given_name":           "Max",
		"family_name":          "Mustermann",
		"birthdate":            "1990-05-15",
		"place_of_birth":       "Berlin",
		"nationality":          "DE",
		"resident_address":     "Musterstraße 123, 10115 Berlin",
		"document_number":      "T22000129",
		"issuing_jurisdiction": "Berlin",
	}

	// Create disclosure frame - personal data is selectively disclosable
	frame := &sdjwt.DisclosureFrame{
		SD: []string{
			"given_name", "family_name", "birthdate", "place_of_birth",
			"nationality", "resident_address", "document_number", "issuing_jurisdiction",
		},
	}

	// Issue QEAA
	now := time.Now()
	admNbf := now.Add(-30 * 24 * time.Hour) // Administrative validity started 30 days ago
	admExp := now.Add(335 * 24 * time.Hour) // Administrative validity ends in 335 days

	qeaa, err := qeaaIssuer.Issue(claims, frame, sdjwtvc.EAAIssueOptions{
		VCT:                      "https://example.eu/credentials/EUIdentityCredential",
		VCTIntegrity:             "sha256-abc123def456",
		JTI:                      "urn:uuid:6c5c0a49-b589-431d-bae7-219122a9ec2c",
		Subject:                  "urn:de:bund:personalausweis:T22000129",
		NotBefore:                now,
		ExpirationTime:           now.Add(365 * 24 * time.Hour),
		AdministrativeNotBefore:  &admNbf,
		AdministrativeExpiration: &admExp,
		HolderPublicKey:          holderPubJWK,
		Status: &sdjwtvc.EAAStatus{
			Type:    sdjwtvc.StatusTypeTokenStatusList,
			Purpose: "revocation",
			Index:   42,
			URI:     "https://qualified-issuer.example.eu/status/identity/1",
		},
	})
	if err != nil {
		log.Fatalf("Failed to issue QEAA: %v", err)
	}

	qeaaSerialized := qeaa.Serialize()
	fmt.Printf("\n  QEAA issued successfully!\n")
	fmt.Printf("    Disclosures: %d\n", len(qeaa.Disclosures))
	fmt.Printf("    Token length: %d bytes\n", len(qeaaSerialized))
	fmt.Printf("    [QEAA SD-JWT Token]:\n%s\n", qeaaSerialized)

	// Parse and show JWT headers (should contain x5u, x5t#S256, x5c)
	token, _, _ := new(jwt.Parser).ParseUnverified(qeaa.IssuerSignedJWT, jwt.MapClaims{})
	fmt.Println("\n  JWT Headers (X.509 for QEAA):")
	if x5u, ok := token.Header["x5u"]; ok {
		fmt.Printf("    x5u: %v\n", x5u)
	}
	if x5ts256, ok := token.Header["x5t#S256"]; ok {
		fmt.Printf("    x5t#S256: %v\n", x5ts256)
	}
	if x5c, ok := token.Header["x5c"]; ok {
		x5cArr := x5c.([]interface{})
		fmt.Printf("    x5c: [%d certificate(s)]\n", len(x5cArr))
	}

	// Show claims structure
	tokenClaims := token.Claims.(jwt.MapClaims)
	fmt.Println("\n  QEAA Claims Structure:")
	fmt.Printf("    vct: %v\n", tokenClaims["vct"])
	fmt.Printf("    vct#integrity: %v\n", tokenClaims["vct#integrity"])
	fmt.Printf("    jti: %v\n", tokenClaims["jti"])
	fmt.Printf("    category: %v\n", tokenClaims["category"])
	fmt.Printf("    issuing_authority: %v\n", tokenClaims["issuing_authority"])
	fmt.Printf("    issuing_country: %v\n", tokenClaims["issuing_country"])
	fmt.Printf("    iss_reg_id: %v\n", tokenClaims["iss_reg_id"])
	if status, ok := tokenClaims["status"].(map[string]any); ok {
		fmt.Printf("    status.type: %v\n", status["type"])
		fmt.Printf("    status.purpose: %v\n", status["purpose"])
		fmt.Printf("    status.index: %v\n", status["index"])
	}

	// === PuB-EAA (Public Body EAA) Issuer ===
	fmt.Println("\n  [PuB-EAA] Creating Public Body EAA...")

	pubEAAIssuer, err := sdjwtvc.NewEAAIssuer(sdjwtvc.EAAIssuerConfig{
		Category:              sdjwtvc.EAACategoryPuBEAA,
		IssuerID:              "https://education.example.gov",
		IssuingAuthority:      "Ministry of Education",
		IssuingCountry:        "FR",
		IssuerRegistrationID:  "FRMIN-EDU-001",
		Signer:                issuerSigner,
		SigningCertificate:    cert,
		SigningCertificateURL: "https://education.example.gov/certs/signing.pem",
	})
	if err != nil {
		log.Fatalf("Failed to create PuB-EAA issuer: %v", err)
	}

	// Educational credential claims
	eduClaims := map[string]any{
		"degree_type":     "Master of Science",
		"degree_field":    "Computer Science",
		"institution":     "University of Paris",
		"graduation_date": "2023-06-15",
		"honors":          "Magna Cum Laude",
	}

	eduFrame := sdjwt.NewDisclosureFrame("degree_type", "degree_field", "institution", "graduation_date", "honors")

	pubEAA, err := pubEAAIssuer.Issue(eduClaims, eduFrame, sdjwtvc.EAAIssueOptions{
		VCT:            "https://example.eu/credentials/EducationCredential",
		VCTIntegrity:   "sha256-edu789xyz",
		JTI:            "urn:uuid:7d6d1b5a-c69a-542e-cbf8-320233b0fd3d",
		Subject:        "urn:fr:education:student:12345",
		NotBefore:      now,
		ExpirationTime: now.Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		Status: &sdjwtvc.EAAStatus{
			Type:    sdjwtvc.StatusTypeBitstringStatusList,
			Purpose: "revocation",
			Index:   100,
			URI:     "https://education.example.gov/status/degrees/1",
		},
	})
	if err != nil {
		log.Fatalf("Failed to issue PuB-EAA: %v", err)
	}

	pubEAASerialized := pubEAA.Serialize()
	fmt.Printf("\n  PuB-EAA issued: %d disclosures\n", len(pubEAA.Disclosures))
	fmt.Printf("    Category: PuB-EAA (%s)\n", sdjwtvc.CategoryPuBEAA)
	fmt.Printf("    [PuB-EAA SD-JWT Token]:\n%s\n", pubEAASerialized)

	// === Regular EAA (non-qualified) ===
	fmt.Println("\n  [Regular EAA] Creating non-qualified EAA...")

	regularIssuer, err := sdjwtvc.NewEAAIssuer(sdjwtvc.EAAIssuerConfig{
		Category: sdjwtvc.EAACategoryRegular,
		IssuerID: "https://loyalty.example.com",
		Signer:   issuerSigner,
	})
	if err != nil {
		log.Fatalf("Failed to create regular EAA issuer: %v", err)
	}

	loyaltyClaims := map[string]any{
		"membership_level": "Gold",
		"points_balance":   15000,
		"member_since":     "2020-01-15",
	}

	loyaltyFrame := sdjwt.NewDisclosureFrame("membership_level", "points_balance", "member_since")

	regularEAA, err := regularIssuer.Issue(loyaltyClaims, loyaltyFrame, sdjwtvc.EAAIssueOptions{
		VCT:            "https://loyalty.example.com/credentials/MembershipCredential",
		VCTIntegrity:   "sha256-loyalty123",
		JTI:            "urn:uuid:8e7e2c6b-d7ab-653f-dcg9-431344c1ge4e",
		Subject:        "urn:loyalty:member:67890",
		NotBefore:      now,
		ExpirationTime: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		log.Fatalf("Failed to issue regular EAA: %v", err)
	}

	regularEAASerialized := regularEAA.Serialize()
	fmt.Printf("  Regular EAA issued: %d disclosures\n", len(regularEAA.Disclosures))
	fmt.Println("    (No category claim - regular EAA)")
	fmt.Printf("    [Regular EAA SD-JWT Token]:\n%s\n", regularEAASerialized)

	// === EAA with Pseudonym ===
	fmt.Println("\n  [Pseudonym EAA] Creating EAA with pseudonym instead of subject...")

	pseudonymEAA, err := regularIssuer.Issue(loyaltyClaims, loyaltyFrame, sdjwtvc.EAAIssueOptions{
		VCT:            "https://loyalty.example.com/credentials/MembershipCredential",
		VCTIntegrity:   "sha256-loyalty123",
		JTI:            "urn:uuid:9f8f3d7c-e8bc-764g-edh0-542455d2hf5f",
		Pseudonym:      "anon-member-xyz789", // Using pseudonym instead of subject
		NotBefore:      now,
		ExpirationTime: now.Add(365 * 24 * time.Hour),
	})
	if err != nil {
		log.Fatalf("Failed to issue pseudonym EAA: %v", err)
	}

	pseudonymEAASerialized := pseudonymEAA.Serialize()
	pseudonymToken, _, _ := new(jwt.Parser).ParseUnverified(pseudonymEAA.IssuerSignedJWT, jwt.MapClaims{})
	pseudonymClaims := pseudonymToken.Claims.(jwt.MapClaims)
	fmt.Printf("  Pseudonym EAA issued\n")
	fmt.Printf("    also_known_as: %v\n", pseudonymClaims["also_known_as"])
	fmt.Printf("    (No sub claim)\n")
	fmt.Printf("    [Pseudonym EAA SD-JWT Token]:\n%s\n", pseudonymEAASerialized)

	// === EAA with Usage Constraints ===
	fmt.Println("\n  [One-Time EAA] Creating one-time use EAA...")

	oneTimeEAA, err := regularIssuer.Issue(nil, nil, sdjwtvc.EAAIssueOptions{
		VCT:            "https://example.com/credentials/OneTimeToken",
		VCTIntegrity:   "sha256-onetime123",
		JTI:            "urn:uuid:0a9a4e8d-f9cd-875h-fei1-653566e3ig6g",
		Subject:        "urn:user:temp123",
		NotBefore:      now,
		ExpirationTime: now.Add(1 * time.Hour), // Short-lived
		OneTime:        true,
		ShortLived:     true,
	})
	if err != nil {
		log.Fatalf("Failed to issue one-time EAA: %v", err)
	}

	oneTimeEAASerialized := oneTimeEAA.Serialize()
	oneTimeToken, _, _ := new(jwt.Parser).ParseUnverified(oneTimeEAA.IssuerSignedJWT, jwt.MapClaims{})
	oneTimeClaims := oneTimeToken.Claims.(jwt.MapClaims)
	fmt.Printf("  One-time EAA issued\n")
	_, hasOneTime := oneTimeClaims["oneTime"]
	_, hasShortLived := oneTimeClaims["shortLived"]
	fmt.Printf("    oneTime claim present: %v (value is JSON null)\n", hasOneTime)
	fmt.Printf("    shortLived claim present: %v (value is JSON null)\n", hasShortLived)
	fmt.Printf("    [One-Time EAA SD-JWT Token]:\n%s\n", oneTimeEAASerialized)

	// === EAA Validation ===
	fmt.Println("\n  [Validation] Validating QEAA payload...")

	// Get claims for validation
	validateClaims := tokenClaims

	// Validate as QEAA
	qeaaCategory := sdjwtvc.EAACategoryQEAA
	err = sdjwtvc.ValidateEAA(validateClaims, &sdjwtvc.EAAValidationOptions{
		ExpectedCategory: &qeaaCategory,
	})
	if err != nil {
		fmt.Printf("    QEAA validation failed: %v\n", err)
	} else {
		fmt.Println("    QEAA validation: PASSED")
	}

	// === Selective Disclosure Rules ===
	fmt.Println("\n  [SD Rules] ETSI EAA Selective Disclosure Rules:")
	testClaimsEAA := []string{"jti", "vct", "category", "issuing_authority", "given_name", "birthdate", "sub", "also_known_as"}
	for _, claim := range testClaimsEAA {
		canSD := sdjwtvc.IsEAAClaimSelectivelyDisclosable(claim)
		status := "CAN be selectively disclosed"
		if !canSD {
			status = "MUST NOT be selectively disclosed"
		}
		fmt.Printf("    %s: %s\n", claim, status)
	}

	// === Holder Presentation ===
	fmt.Println("\n  [Presentation] Creating QEAA presentation...")

	// QEAA Presentation
	h := holder.NewHolder(qeaa)
	presFrame := sdjwt.NewPresentationFrame("given_name", "family_name", "nationality")

	presentation, err := h.PresentWithFrame(
		presFrame,
		holderSigner,
		holder.KeyBindingOptions{
			Audience: "https://border-control.example.eu",
			Nonce:    "qeaa-presentation-nonce-123",
		},
	)
	if err != nil {
		log.Fatalf("Failed to create QEAA presentation: %v", err)
	}

	presentationSerialized := holder.SerializePresentation(presentation)
	fmt.Printf("    Presentation created with %d disclosures\n", len(presentation.SDJWT.Disclosures))
	fmt.Printf("    [QEAA Presentation SD-JWT]:\n%s\n", presentationSerialized)

	// PuB-EAA Presentation
	fmt.Println("\n  [Presentation] Creating PuB-EAA presentation...")
	hPub := holder.NewHolder(pubEAA)
	presFramePub := sdjwt.NewPresentationFrame("degree_type", "degree_field")
	pubPresentation, err := hPub.PresentWithFrame(
		presFramePub,
		holderSigner,
		holder.KeyBindingOptions{
			Audience: "https://qualifications-verifier.example.com",
			Nonce:    "pubeaa-presentation-nonce-001",
		},
	)
	if err != nil {
		log.Fatalf("Failed to create PuB-EAA presentation: %v", err)
	}
	pubPresentationSerialized := holder.SerializePresentation(pubPresentation)
	fmt.Printf("    PuB-EAA Presentation created with %d disclosures\n", len(pubPresentation.SDJWT.Disclosures))
	fmt.Printf("    [PuB-EAA Presentation SD-JWT]:\n%s\n", pubPresentationSerialized)

	// Regular EAA Presentation
	fmt.Println("\n  [Presentation] Creating Regular EAA presentation...")
	hReg := holder.NewHolder(regularEAA)
	presFrameReg := sdjwt.NewPresentationFrame("membership_level", "points_balance")
	regularPresentation, err := hReg.PresentWithFrame(
		presFrameReg,
		holderSigner,
		holder.KeyBindingOptions{
			Audience: "https://loyalty-verifier.example.com",
			Nonce:    "regulareaa-presentation-nonce-222",
		},
	)
	if err != nil {
		log.Fatalf("Failed to create Regular EAA presentation: %v", err)
	}
	regularPresentationSerialized := holder.SerializePresentation(regularPresentation)
	fmt.Printf("    Regular EAA Presentation created with %d disclosures\n", len(regularPresentation.SDJWT.Disclosures))
	fmt.Printf("    [Regular EAA Presentation SD-JWT]:\n%s\n", regularPresentationSerialized)

	// Pseudonym EAA Presentation
	fmt.Println("\n  [Presentation] Creating Pseudonym EAA presentation...")
	hPseudo := holder.NewHolder(pseudonymEAA)
	presFramePseudo := sdjwt.NewPresentationFrame("membership_level")
	pseudonymPresentation, err := hPseudo.PresentWithFrame(
		presFramePseudo,
		holderSigner,
		holder.KeyBindingOptions{
			Audience: "https://anonymous-verifier.example.com",
			Nonce:    "pseudo-presentation-nonce-333",
		},
	)
	if err != nil {
		log.Fatalf("Failed to create Pseudonym EAA presentation: %v", err)
	}
	pseudonymPresentationSerialized := holder.SerializePresentation(pseudonymPresentation)
	fmt.Printf("    Pseudonym EAA Presentation created with %d disclosures\n", len(pseudonymPresentation.SDJWT.Disclosures))
	fmt.Printf("    [Pseudonym EAA Presentation SD-JWT]:\n%s\n", pseudonymPresentationSerialized)

	// One-Time EAA Presentation
	fmt.Println("\n  [Presentation] Creating One-Time EAA presentation...")
	hOneTime := holder.NewHolder(oneTimeEAA)
	presFrameOneTime := sdjwt.NewPresentationFrame()
	oneTimePresentation, err := hOneTime.PresentWithFrame(
		presFrameOneTime,
		holderSigner,
		holder.KeyBindingOptions{
			Audience: "https://onetime-verifier.example.com",
			Nonce:    "onetime-presentation-nonce-444",
		},
	)
	if err != nil {
		log.Fatalf("Failed to create One-Time EAA presentation: %v", err)
	}
	oneTimePresentationSerialized := holder.SerializePresentation(oneTimePresentation)
	fmt.Printf("    One-Time EAA Presentation created with %d disclosures\n", len(oneTimePresentation.SDJWT.Disclosures))
	fmt.Printf("    [One-Time EAA Presentation SD-JWT]:\n%s\n", oneTimePresentationSerialized)

	// Verify presentation (QEAA example)
	v := verifier.NewVerifier(issuerSigner)
	result, err := v.VerifyWithKeyBinding(presentationSerialized, presFrame, &verifier.KeyBindingRequirement{
		Nonce:    "qeaa-presentation-nonce-123",
		Audience: "https://border-control.example.eu",
	})
	if err != nil {
		log.Fatalf("QEAA verification failed: %v", err)
	}

	fmt.Printf("\n  QEAA Verification Result:\n")
	fmt.Printf("    Valid: %v\n", result.Valid)
	fmt.Printf("    Key Binding Valid: %v\n", *result.KeyBindingValid)
	fmt.Printf("    Disclosed Claims: %v\n", result.DisclosedClaims)

	fmt.Println("\n  ETSI EAA demo complete!")
}
