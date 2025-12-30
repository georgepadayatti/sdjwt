package sdjwtvc

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/golang-jwt/jwt/v5"
)

type signerWithoutCert struct {
	base signer.Signer
}

func (s *signerWithoutCert) Sign(signingInput string) ([]byte, error) {
	return s.base.Sign(signingInput)
}

func (s *signerWithoutCert) Algorithm() string {
	return s.base.Algorithm()
}

func (s *signerWithoutCert) PublicKey() crypto.PublicKey {
	return s.base.PublicKey()
}

func (s *signerWithoutCert) Certificate() *x509.Certificate {
	return nil
}

func (s *signerWithoutCert) CertificateChain() []*x509.Certificate {
	return nil
}

func newTestSigner(t *testing.T) (signer.Signer, *x509.Certificate, []*x509.Certificate) {
	t.Helper()
	s, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	cert := s.Certificate()
	if cert == nil {
		t.Fatal("default signer did not provide a certificate")
	}
	chain := s.CertificateChain()
	if len(chain) == 0 {
		chain = []*x509.Certificate{cert}
	}
	return s, cert, chain
}

func newSignerWithoutCert(t *testing.T) signer.Signer {
	t.Helper()
	s, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return &signerWithoutCert{base: s}
}

func TestNewEAAIssuer(t *testing.T) {
	issuerSigner, cert, chain := newTestSigner(t)

	t.Run("Regular EAA issuer", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}
		if issuer == nil {
			t.Fatal("NewEAAIssuer() returned nil")
		}
	})

	t.Run("QEAA issuer requires all fields", func(t *testing.T) {
		noCertSigner := newSignerWithoutCert(t)
		config := EAAIssuerConfig{
			Category: EAACategoryQEAA,
			IssuerID: "https://issuer.example.com",
			Signer:   noCertSigner,
			// Missing IssuingAuthority, IssuingCountry, SigningCertificateURL, SigningCertificate
		}

		_, err := NewEAAIssuer(config)
		if err == nil {
			t.Fatal("Expected error for QEAA without required fields")
		}
	})

	t.Run("QEAA issuer with all required fields", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category:                EAACategoryQEAA,
			IssuerID:                "https://issuer.example.com",
			IssuingAuthority:        "German Federal Authority",
			IssuingCountry:          "DE",
			Signer:                  issuerSigner,
			SigningCertificate:      cert,
			SigningCertificateChain: chain,
			SigningCertificateURL:   "https://issuer.example.com/cert",
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}
		if issuer == nil {
			t.Fatal("NewEAAIssuer() returned nil")
		}
	})

	t.Run("IssuerID is required", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			Signer:   issuerSigner,
		}

		_, err := NewEAAIssuer(config)
		if err == nil {
			t.Fatal("Expected error for missing IssuerID")
		}
	})
}

func TestEAAIssuerIssue(t *testing.T) {
	issuerSigner, cert, chain := newTestSigner(t)

	t.Run("Issue regular EAA", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		claims := map[string]any{
			"given_name":  "Max",
			"family_name": "Mustermann",
		}

		frame := sdjwt.NewDisclosureFrame("given_name", "family_name")

		now := time.Now()
		opts := EAAIssueOptions{
			VCT:            "https://example.com/credentials/IdentityCredential",
			VCTIntegrity:   "sha256-abcdef123456",
			JTI:            "urn:uuid:12345678-1234-1234-1234-123456789abc",
			Subject:        "urn:user:max.mustermann",
			NotBefore:      now,
			ExpirationTime: now.Add(365 * 24 * time.Hour),
		}

		sdj, err := issuer.Issue(claims, frame, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		if sdj == nil {
			t.Fatal("Issue() returned nil")
		}

		// Verify disclosures were created
		if len(sdj.Disclosures) != 2 {
			t.Errorf("Expected 2 disclosures, got %d", len(sdj.Disclosures))
		}
	})

	t.Run("Issue QEAA with all required fields", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category:                EAACategoryQEAA,
			IssuerID:                "https://issuer.example.com",
			IssuingAuthority:        "German Federal Authority",
			IssuingCountry:          "DE",
			IssuerRegistrationID:    "NTDE-HRB12345",
			Signer:                  issuerSigner,
			SigningCertificate:      cert,
			SigningCertificateChain: chain,
			SigningCertificateURL:   "https://issuer.example.com/cert",
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		claims := map[string]any{
			"given_name":  "Max",
			"family_name": "Mustermann",
			"birthdate":   "1990-01-15",
		}

		frame := sdjwt.NewDisclosureFrame("given_name", "family_name", "birthdate")

		now := time.Now()
		opts := EAAIssueOptions{
			VCT:            "https://example.com/credentials/IdentityCredential",
			VCTIntegrity:   "sha256-abcdef123456",
			JTI:            "urn:uuid:12345678-1234-1234-1234-123456789abc",
			Subject:        "urn:user:max.mustermann",
			NotBefore:      now,
			ExpirationTime: now.Add(365 * 24 * time.Hour),
			Status: &EAAStatus{
				Type:    StatusTypeTokenStatusList,
				Purpose: "revocation",
				Index:   42,
				URI:     "https://issuer.example.com/status/1",
			},
		}

		sdj, err := issuer.Issue(claims, frame, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Parse the JWT to verify the claims
		token, _, err := new(jwt.Parser).ParseUnverified(sdj.IssuerSignedJWT, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse JWT: %v", err)
		}

		tokenClaims := token.Claims.(jwt.MapClaims)

		// Check category
		if tokenClaims["category"] != CategoryQEAA {
			t.Errorf("Expected category %q, got %q", CategoryQEAA, tokenClaims["category"])
		}

		// Check issuing authority and country
		if tokenClaims["issuing_authority"] != "German Federal Authority" {
			t.Errorf("Expected issuing_authority %q, got %q", "German Federal Authority", tokenClaims["issuing_authority"])
		}
		if tokenClaims["issuing_country"] != "DE" {
			t.Errorf("Expected issuing_country %q, got %q", "DE", tokenClaims["issuing_country"])
		}

		// Check status structure
		status, ok := tokenClaims["status"].(map[string]any)
		if !ok {
			t.Fatal("status claim missing or not a map")
		}
		if status["type"] != StatusTypeTokenStatusList {
			t.Errorf("Expected status.type %q, got %q", StatusTypeTokenStatusList, status["type"])
		}
		if status["purpose"] != "revocation" {
			t.Errorf("Expected status.purpose %q, got %q", "revocation", status["purpose"])
		}

		// Check X.509 headers
		if token.Header["x5u"] != "https://issuer.example.com/cert" {
			t.Errorf("Expected x5u header, got %v", token.Header["x5u"])
		}
		if _, ok := token.Header["x5t#S256"]; !ok {
			t.Error("Expected x5t#S256 header")
		}
	})

	t.Run("Issue EAA with pseudonym instead of subject", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		claims := map[string]any{
			"given_name": "Max",
		}

		now := time.Now()
		opts := EAAIssueOptions{
			VCT:            "https://example.com/credentials/IdentityCredential",
			VCTIntegrity:   "sha256-abcdef123456",
			JTI:            "urn:uuid:12345678-1234-1234-1234-123456789abc",
			Pseudonym:      "anon-user-12345",
			NotBefore:      now,
			ExpirationTime: now.Add(365 * 24 * time.Hour),
		}

		sdj, err := issuer.Issue(claims, nil, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Parse and verify
		token, _, err := new(jwt.Parser).ParseUnverified(sdj.IssuerSignedJWT, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse JWT: %v", err)
		}

		tokenClaims := token.Claims.(jwt.MapClaims)
		if tokenClaims["also_known_as"] != "anon-user-12345" {
			t.Errorf("Expected also_known_as %q, got %q", "anon-user-12345", tokenClaims["also_known_as"])
		}
	})

	t.Run("Issue EAA with administrative validity", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		now := time.Now()
		admNbf := now.Add(-30 * 24 * time.Hour) // Started 30 days ago
		admExp := now.Add(335 * 24 * time.Hour) // Expires in 335 days

		opts := EAAIssueOptions{
			VCT:                      "https://example.com/credentials/IdentityCredential",
			VCTIntegrity:             "sha256-abcdef123456",
			JTI:                      "urn:uuid:12345678-1234-1234-1234-123456789abc",
			Subject:                  "urn:user:max.mustermann",
			NotBefore:                now,
			ExpirationTime:           now.Add(365 * 24 * time.Hour),
			AdministrativeNotBefore:  &admNbf,
			AdministrativeExpiration: &admExp,
		}

		sdj, err := issuer.Issue(nil, nil, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Parse and verify
		token, _, err := new(jwt.Parser).ParseUnverified(sdj.IssuerSignedJWT, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse JWT: %v", err)
		}

		tokenClaims := token.Claims.(jwt.MapClaims)
		if _, ok := tokenClaims["adm_nbf"]; !ok {
			t.Error("Expected adm_nbf claim")
		}
		if _, ok := tokenClaims["adm_exp"]; !ok {
			t.Error("Expected adm_exp claim")
		}
	})

	t.Run("Issue EAA with oneTime and shortLived", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		now := time.Now()
		opts := EAAIssueOptions{
			VCT:            "https://example.com/credentials/IdentityCredential",
			VCTIntegrity:   "sha256-abcdef123456",
			JTI:            "urn:uuid:12345678-1234-1234-1234-123456789abc",
			Subject:        "urn:user:max.mustermann",
			NotBefore:      now,
			ExpirationTime: now.Add(1 * time.Hour), // Short-lived
			OneTime:        true,
			ShortLived:     true,
		}

		sdj, err := issuer.Issue(nil, nil, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Parse and verify - oneTime and shortLived should be JSON null
		token, _, err := new(jwt.Parser).ParseUnverified(sdj.IssuerSignedJWT, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse JWT: %v", err)
		}

		tokenClaims := token.Claims.(jwt.MapClaims)
		if _, ok := tokenClaims["oneTime"]; !ok {
			t.Error("Expected oneTime claim")
		}
		if _, ok := tokenClaims["shortLived"]; !ok {
			t.Error("Expected shortLived claim")
		}
	})

	t.Run("Issue EAA with subAttrs", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		now := time.Now()
		opts := EAAIssueOptions{
			VCT:            "https://example.com/credentials/CompanyCredential",
			VCTIntegrity:   "sha256-abcdef123456",
			JTI:            "urn:uuid:12345678-1234-1234-1234-123456789abc",
			Subject:        "urn:user:max.mustermann",
			NotBefore:      now,
			ExpirationTime: now.Add(365 * 24 * time.Hour),
			SubjectAttributes: []SubjectAttributes{
				{
					SubjectID: "urn:company:acme-corp",
					Attributes: []any{
						map[string]any{"role": "CEO"},
						map[string]any{"department": "Executive"},
					},
				},
			},
		}

		sdj, err := issuer.Issue(nil, nil, opts)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		// Parse and verify
		token, _, err := new(jwt.Parser).ParseUnverified(sdj.IssuerSignedJWT, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("Failed to parse JWT: %v", err)
		}

		tokenClaims := token.Claims.(jwt.MapClaims)
		subAttrs, ok := tokenClaims["subAttrs"].([]any)
		if !ok {
			t.Fatal("Expected subAttrs claim to be array")
		}
		if len(subAttrs) != 1 {
			t.Errorf("Expected 1 subAttrs entry, got %d", len(subAttrs))
		}
	})

	t.Run("Validation errors", func(t *testing.T) {
		config := EAAIssuerConfig{
			Category: EAACategoryRegular,
			IssuerID: "https://issuer.example.com",
			Signer:   issuerSigner,
		}

		issuer, err := NewEAAIssuer(config)
		if err != nil {
			t.Fatalf("NewEAAIssuer() error = %v", err)
		}

		now := time.Now()

		// Missing VCT
		opts := EAAIssueOptions{
			JTI:            "urn:uuid:12345678",
			Subject:        "urn:user:test",
			NotBefore:      now,
			ExpirationTime: now.Add(time.Hour),
		}
		_, err = issuer.Issue(nil, nil, opts)
		if err == nil {
			t.Error("Expected error for missing VCT")
		}

		// Missing JTI
		opts = EAAIssueOptions{
			VCT:            "https://example.com/credentials/Test",
			VCTIntegrity:   "sha256-test",
			Subject:        "urn:user:test",
			NotBefore:      now,
			ExpirationTime: now.Add(time.Hour),
		}
		_, err = issuer.Issue(nil, nil, opts)
		if err == nil {
			t.Error("Expected error for missing JTI")
		}

		// Missing both Subject and Pseudonym
		opts = EAAIssueOptions{
			VCT:            "https://example.com/credentials/Test",
			VCTIntegrity:   "sha256-test",
			JTI:            "urn:uuid:12345678",
			NotBefore:      now,
			ExpirationTime: now.Add(time.Hour),
		}
		_, err = issuer.Issue(nil, nil, opts)
		if err == nil {
			t.Error("Expected error for missing Subject and Pseudonym")
		}

		// Only AdministrativeNotBefore set (AdministrativeExpiration missing)
		admNbf := now
		opts = EAAIssueOptions{
			VCT:                     "https://example.com/credentials/Test",
			VCTIntegrity:            "sha256-test",
			JTI:                     "urn:uuid:12345678",
			Subject:                 "urn:user:test",
			NotBefore:               now,
			ExpirationTime:          now.Add(time.Hour),
			AdministrativeNotBefore: &admNbf,
		}
		_, err = issuer.Issue(nil, nil, opts)
		if err == nil {
			t.Error("Expected error for AdministrativeNotBefore without AdministrativeExpiration")
		}
	})
}

func TestValidateEAA(t *testing.T) {
	now := time.Now()
	nowUnix := now.Unix()

	t.Run("Valid EAA payload", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
		}

		err := ValidateEAA(payload, nil)
		if err != nil {
			t.Errorf("ValidateEAA() error = %v", err)
		}
	})

	t.Run("Valid EAA with pseudonym", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"also_known_as": "anon-12345",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
		}

		err := ValidateEAA(payload, nil)
		if err != nil {
			t.Errorf("ValidateEAA() error = %v", err)
		}
	})

	t.Run("Missing vct", func(t *testing.T) {
		payload := map[string]any{
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for missing vct")
		}
	})

	t.Run("Missing vct#integrity", func(t *testing.T) {
		payload := map[string]any{
			"vct": "https://example.com/credentials/Test",
			"iss": "https://issuer.example.com",
			"jti": "urn:uuid:12345678",
			"sub": "urn:user:test",
			"nbf": nowUnix - 3600,
			"exp": nowUnix + 3600,
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for missing vct#integrity")
		}
	})

	t.Run("Missing jti", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for missing jti")
		}
	})

	t.Run("Missing both sub and also_known_as", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for missing sub and also_known_as")
		}
	})

	t.Run("QEAA validation", func(t *testing.T) {
		// Valid QEAA
		payload := map[string]any{
			"vct":               "https://example.com/credentials/Test",
			"vct#integrity":     "sha256-test",
			"iss":               "https://issuer.example.com",
			"jti":               "urn:uuid:12345678",
			"sub":               "urn:user:test",
			"nbf":               nowUnix - 3600,
			"exp":               nowUnix + 3600,
			"category":          CategoryQEAA,
			"issuing_authority": "German Authority",
			"issuing_country":   "DE",
			"status": map[string]any{
				"type":    StatusTypeTokenStatusList,
				"purpose": "revocation",
				"index":   42,
				"uri":     "https://issuer.example.com/status",
			},
		}

		qeaaCategory := EAACategoryQEAA
		opts := &EAAValidationOptions{
			ExpectedCategory: &qeaaCategory,
		}

		err := ValidateEAA(payload, opts)
		if err != nil {
			t.Errorf("ValidateEAA() error = %v", err)
		}
	})

	t.Run("QEAA missing issuing_authority", func(t *testing.T) {
		payload := map[string]any{
			"vct":             "https://example.com/credentials/Test",
			"vct#integrity":   "sha256-test",
			"iss":             "https://issuer.example.com",
			"jti":             "urn:uuid:12345678",
			"sub":             "urn:user:test",
			"nbf":             nowUnix - 3600,
			"exp":             nowUnix + 3600,
			"category":        CategoryQEAA,
			"issuing_country": "DE",
			"status": map[string]any{
				"type":    StatusTypeTokenStatusList,
				"purpose": "revocation",
				"index":   42,
				"uri":     "https://issuer.example.com/status",
			},
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for QEAA missing issuing_authority")
		}
	})

	t.Run("Administrative validity - both required", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
			"adm_nbf":       nowUnix - 3600,
			// Missing adm_exp
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for adm_nbf without adm_exp")
		}
	})

	t.Run("Status validation", func(t *testing.T) {
		// Missing type
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
			"status": map[string]any{
				"purpose": "revocation",
				"index":   42,
				"uri":     "https://issuer.example.com/status",
			},
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for status missing type")
		}
	})

	t.Run("subAttrs validation", func(t *testing.T) {
		// Missing both sub_id and sub_aka
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
			"subAttrs": []any{
				map[string]any{
					"attrs": []any{"test"},
				},
			},
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for subAttrs missing sub_id/sub_aka")
		}
	})

	t.Run("CNF validation - x5u without x5t#S256", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
			"cnf": map[string]any{
				"x5u": "https://example.com/cert",
			},
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for cnf.x5u without x5t#S256")
		}
	})

	t.Run("CNF validation - x5c with x5u should error", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 3600,
			"exp":           nowUnix + 3600,
			"cnf": map[string]any{
				"x5c": []string{"MIIC..."},
				"x5u": "https://example.com/cert",
			},
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for cnf with both x5c and x5u")
		}
	})

	t.Run("Expired EAA", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 7200,
			"exp":           nowUnix - 3600, // Expired 1 hour ago
		}

		err := ValidateEAA(payload, nil)
		if err == nil {
			t.Error("Expected error for expired EAA")
		}
	})

	t.Run("Skip expiration check", func(t *testing.T) {
		payload := map[string]any{
			"vct":           "https://example.com/credentials/Test",
			"vct#integrity": "sha256-test",
			"iss":           "https://issuer.example.com",
			"jti":           "urn:uuid:12345678",
			"sub":           "urn:user:test",
			"nbf":           nowUnix - 7200,
			"exp":           nowUnix - 3600, // Expired
		}

		opts := &EAAValidationOptions{
			SkipExpirationCheck: true,
		}

		err := ValidateEAA(payload, opts)
		if err != nil {
			t.Errorf("Expected no error with SkipExpirationCheck, got: %v", err)
		}
	})
}

func TestIsEAAClaimSelectivelyDisclosable(t *testing.T) {
	// Claims that MUST NOT be selectively disclosable
	mustNotDisclose := []string{
		"iss", "vct", "vct#integrity", "jti", "nbf", "exp",
		"category", "issuing_authority", "issuing_country", "iss_reg_id",
		"adm_nbf", "adm_exp", "cnf", "status", "oneTime", "shortLived",
	}

	for _, claim := range mustNotDisclose {
		if IsEAAClaimSelectivelyDisclosable(claim) {
			t.Errorf("Claim %q should NOT be selectively disclosable", claim)
		}
	}

	// Claims that MAY be selectively disclosable
	mayDisclose := []string{"sub", "also_known_as", "iat", "subAttrs", "given_name", "family_name"}

	for _, claim := range mayDisclose {
		if !IsEAAClaimSelectivelyDisclosable(claim) {
			t.Errorf("Claim %q should be selectively disclosable", claim)
		}
	}
}

func TestComputeCertThumbprint(t *testing.T) {
	_, cert, _ := newTestSigner(t)

	thumbprint := computeCertThumbprint(cert)
	if thumbprint == "" {
		t.Error("Expected non-empty thumbprint")
	}

	// Thumbprint should be base64url encoded (no padding)
	if len(thumbprint) != 43 { // SHA-256 is 32 bytes, base64url encoded without padding
		t.Errorf("Expected thumbprint length 43, got %d", len(thumbprint))
	}
}

func TestEAAStatusMarshalJSON(t *testing.T) {
	status := EAAStatus{
		Type:    StatusTypeTokenStatusList,
		Purpose: "revocation",
		Index:   42,
		URI:     "https://issuer.example.com/status/1",
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed["type"] != StatusTypeTokenStatusList {
		t.Errorf("Expected type %q, got %v", StatusTypeTokenStatusList, parsed["type"])
	}
	if parsed["purpose"] != "revocation" {
		t.Errorf("Expected purpose %q, got %v", "revocation", parsed["purpose"])
	}
	if int(parsed["index"].(float64)) != 42 {
		t.Errorf("Expected index 42, got %v", parsed["index"])
	}
	if parsed["uri"] != "https://issuer.example.com/status/1" {
		t.Errorf("Expected uri, got %v", parsed["uri"])
	}
}

func TestSubjectAttributesMarshalJSON(t *testing.T) {
	sa := SubjectAttributes{
		SubjectID: "urn:company:acme",
		Attributes: []any{
			map[string]any{"role": "admin"},
		},
	}

	data, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed["sub_id"] != "urn:company:acme" {
		t.Errorf("Expected sub_id, got %v", parsed["sub_id"])
	}
	if _, ok := parsed["attrs"].([]any); !ok {
		t.Error("Expected attrs to be array")
	}
}

func TestEAACNFClaimMarshalJSON(t *testing.T) {
	t.Run("JWK only", func(t *testing.T) {
		cnf := EAACNFClaim{
			JWK: json.RawMessage(`{"kty":"EC","crv":"P-256"}`),
		}

		data, err := json.Marshal(cnf)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if _, ok := parsed["jwk"]; !ok {
			t.Error("Expected jwk field")
		}
	})

	t.Run("X5C only", func(t *testing.T) {
		cnf := EAACNFClaim{
			X5C: []string{"MIIC..."},
		}

		data, err := json.Marshal(cnf)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if _, ok := parsed["x5c"]; !ok {
			t.Error("Expected x5c field")
		}
	})

	t.Run("X5U with X5TS256", func(t *testing.T) {
		cnf := EAACNFClaim{
			X5U:     "https://example.com/cert",
			X5TS256: "thumbprint-here",
		}

		data, err := json.Marshal(cnf)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if _, ok := parsed["x5u"]; !ok {
			t.Error("Expected x5u field")
		}
		if _, ok := parsed["x5t#S256"]; !ok {
			t.Error("Expected x5t#S256 field")
		}
	})
}
