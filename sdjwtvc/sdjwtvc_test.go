package sdjwtvc

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/georgepadayatti/sdjwt/statuslist"
)

func TestNewVCIssuer(t *testing.T) {
	s, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	issuer, err := NewVCIssuer(IssuerConfig{
		IssuerID: "https://issuer.example.com",
		Signer:   s,
	})
	if err != nil {
		t.Fatalf("NewVCIssuer() error = %v", err)
	}

	if issuer == nil {
		t.Fatal("NewVCIssuer() returned nil")
	}
}

func TestVCIssuerIssue(t *testing.T) {
	s, err := signer.NewDefaultSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	issuer, err := NewVCIssuer(IssuerConfig{
		IssuerID: "https://issuer.example.com",
		Signer:   s,
	})
	if err != nil {
		t.Fatalf("NewVCIssuer() error = %v", err)
	}

	t.Run("issue with frame", func(t *testing.T) {
		claims := map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john@example.com",
		}

		frame := &sdjwt.DisclosureFrame{
			SD: []string{"given_name", "family_name", "email"},
		}

		exp := time.Now().Add(365 * 24 * time.Hour)
		sdj, err := issuer.Issue(claims, frame, VCIssueOptions{
			VCT:            "https://example.com/credentials/IdentityCredential",
			Subject:        "user:12345",
			ExpirationTime: &exp,
		})

		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		if sdj == nil {
			t.Fatal("Issue() returned nil")
		}

		// Should have 3 disclosures
		if len(sdj.Disclosures) != 3 {
			t.Errorf("Disclosures count = %d, want 3", len(sdj.Disclosures))
		}

		// Serialize and verify it's valid
		serialized := sdj.Serialize()
		if serialized == "" {
			t.Error("Serialize() returned empty string")
		}
	})

	t.Run("issue without VCT fails", func(t *testing.T) {
		claims := map[string]any{
			"given_name": "John",
		}

		_, err := issuer.Issue(claims, nil, VCIssueOptions{
			// VCT is missing
		})

		if err == nil {
			t.Error("Issue() should fail without VCT")
		}
	})

	t.Run("issue with status reference", func(t *testing.T) {
		claims := map[string]any{
			"given_name": "John",
		}

		frame := &sdjwt.DisclosureFrame{
			SD: []string{"given_name"},
		}

		sdj, err := issuer.Issue(claims, frame, VCIssueOptions{
			VCT: "https://example.com/credentials/IdentityCredential",
			Status: &StatusListReference{
				Index: 42,
				URI:   "https://issuer.example.com/status/1",
			},
		})

		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		if sdj == nil {
			t.Fatal("Issue() returned nil")
		}
	})

	t.Run("issue with holder public key", func(t *testing.T) {
		holderJWK := []byte(`{"kty":"EC","crv":"P-256","x":"test","y":"test"}`)

		claims := map[string]any{
			"given_name": "John",
		}

		sdj, err := issuer.Issue(claims, nil, VCIssueOptions{
			VCT:             "https://example.com/credentials/IdentityCredential",
			HolderPublicKey: holderJWK,
		})

		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		if sdj == nil {
			t.Fatal("Issue() returned nil")
		}
	})

	t.Run("issue with VCT integrity", func(t *testing.T) {
		claims := map[string]any{
			"given_name": "John",
		}

		sdj, err := issuer.Issue(claims, nil, VCIssueOptions{
			VCT:          "https://example.com/credentials/IdentityCredential",
			VCTIntegrity: "sha256-abcdef123456",
		})

		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}

		if sdj == nil {
			t.Fatal("Issue() returned nil")
		}
	})
}

func TestValidateVC(t *testing.T) {
	t.Run("valid VC", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"iat": time.Now().Unix(),
			"nbf": time.Now().Add(-time.Hour).Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		err := ValidateVC(payload)
		if err != nil {
			t.Errorf("ValidateVC() error = %v", err)
		}
	})

	t.Run("valid VC without iss (iss is optional per spec)", func(t *testing.T) {
		payload := map[string]any{
			"vct": "https://example.com/credentials/IdentityCredential",
			"iat": time.Now().Unix(),
		}

		err := ValidateVC(payload)
		if err != nil {
			t.Errorf("ValidateVC() error = %v, iss should be optional", err)
		}
	})

	t.Run("missing vct", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.example.com",
		}

		err := ValidateVC(payload)
		if err == nil {
			t.Error("ValidateVC() should fail without vct")
		}
	})

	t.Run("expired VC", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}

		err := ValidateVC(payload)
		if err == nil {
			t.Error("ValidateVC() should fail for expired VC")
		}
	})

	t.Run("not yet valid VC", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"nbf": time.Now().Add(time.Hour).Unix(),
		}

		err := ValidateVC(payload)
		if err == nil {
			t.Error("ValidateVC() should fail for not-yet-valid VC")
		}
	})

	t.Run("skip expiration check", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}

		err := ValidateVCWithOptions(payload, &ValidationOptions{
			SkipExpirationCheck: true,
		})
		if err != nil {
			t.Errorf("ValidateVCWithOptions() should pass with skip expiration, got error = %v", err)
		}
	})

	t.Run("clock skew tolerance", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"nbf": time.Now().Add(30 * time.Second).Unix(), // 30 seconds in the future
		}

		err := ValidateVCWithOptions(payload, &ValidationOptions{
			AllowedClockSkew: time.Minute, // Allow 1 minute skew
		})
		if err != nil {
			t.Errorf("ValidateVCWithOptions() should pass with clock skew, got error = %v", err)
		}
	})
}

func TestCheckStatus(t *testing.T) {
	t.Run("valid status", func(t *testing.T) {
		// Create a status list
		sl, _ := statuslist.NewStatusList(100, statuslist.Bits1)

		// Create token
		token, _ := statuslist.NewStatusListToken(
			"https://issuer.example.com",
			"https://issuer.example.com/status/1",
			sl,
			time.Now().Unix(),
			time.Now().Add(time.Hour).Unix(),
		)

		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": 42,
					"uri": "https://issuer.example.com/status/1",
				},
			},
		}

		valid, err := CheckStatus(payload, token, 100)
		if err != nil {
			t.Fatalf("CheckStatus() error = %v", err)
		}
		if !valid {
			t.Error("CheckStatus() = false, want true")
		}
	})

	t.Run("revoked status", func(t *testing.T) {
		// Create a status list with revoked entry
		sl, _ := statuslist.NewStatusList(100, statuslist.Bits1)
		sl.SetStatus(42, statuslist.StatusInvalid) // Revoke index 42

		token, _ := statuslist.NewStatusListToken(
			"https://issuer.example.com",
			"https://issuer.example.com/status/1",
			sl,
			time.Now().Unix(),
			time.Now().Add(time.Hour).Unix(),
		)

		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": 42,
					"uri": "https://issuer.example.com/status/1",
				},
			},
		}

		valid, err := CheckStatus(payload, token, 100)
		if err != nil {
			t.Fatalf("CheckStatus() error = %v", err)
		}
		if valid {
			t.Error("CheckStatus() = true, want false (revoked)")
		}
	})

	t.Run("no status claim", func(t *testing.T) {
		// Create a status list
		sl, _ := statuslist.NewStatusList(100, statuslist.Bits1)
		token, _ := statuslist.NewStatusListToken(
			"https://issuer.example.com",
			"https://issuer.example.com/status/1",
			sl,
			time.Now().Unix(),
			time.Now().Add(time.Hour).Unix(),
		)

		payload := map[string]any{
			"iss": "https://issuer.example.com",
			"vct": "https://example.com/credentials/IdentityCredential",
			// No status claim
		}

		valid, err := CheckStatus(payload, token, 100)
		if err != nil {
			t.Fatalf("CheckStatus() error = %v", err)
		}
		if !valid {
			t.Error("CheckStatus() = false, want true (no status means valid)")
		}
	})
}

func TestIsClaimSelectivelyDisclosable(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"iss", false},
		{"vct", false},
		{"vct#integrity", false},
		{"cnf", false},
		{"status", false},
		{"nbf", false},
		{"exp", false},
		{"sub", true}, // MAY be SD
		{"iat", true}, // MAY be SD
		{"given_name", true},
		{"email", true},
		{"custom_claim", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsClaimSelectivelyDisclosable(tt.name); got != tt.want {
				t.Errorf("IsClaimSelectivelyDisclosable(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMustNotBeSelectivelyDisclosed(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"iss", true},
		{"vct", true},
		{"vct#integrity", true},
		{"cnf", true},
		{"status", true},
		{"nbf", true},
		{"exp", true},
		{"sub", false},
		{"iat", false},
		{"given_name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MustNotBeSelectivelyDisclosed(tt.name); got != tt.want {
				t.Errorf("MustNotBeSelectivelyDisclosed(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMayBeSelectivelyDisclosed(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"sub", true},
		{"iat", true},
		{"given_name", true},
		{"iss", false},
		{"vct", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MayBeSelectivelyDisclosed(tt.name); got != tt.want {
				t.Errorf("MayBeSelectivelyDisclosed(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestGetClaimsNotSelectivelyDisclosable(t *testing.T) {
	claims := GetClaimsNotSelectivelyDisclosable()

	if len(claims) == 0 {
		t.Error("GetClaimsNotSelectivelyDisclosable() returned empty slice")
	}

	// Verify we get a copy, not the original
	claims[0] = "modified"
	originalClaims := GetClaimsNotSelectivelyDisclosable()
	if originalClaims[0] == "modified" {
		t.Error("GetClaimsNotSelectivelyDisclosable() returned the original slice, not a copy")
	}

	// Verify vct#integrity is included
	found := false
	for _, c := range originalClaims {
		if c == "vct#integrity" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetClaimsNotSelectivelyDisclosable() should include vct#integrity")
	}
}

func TestVCTMetadata(t *testing.T) {
	metadata := VCTMetadata{
		VCT:              "https://example.com/credentials/IdentityCredential",
		Name:             "Identity Credential",
		Description:      "A credential for identity verification",
		Extends:          []string{"https://example.com/credentials/BaseCredential"},
		ExtendsIntegrity: []string{"sha256-abcdef"},
		Schema:           "https://example.com/schemas/identity.json",
		SchemaIntegrity:  "sha256-123456",
		Display: []DisplayMetadata{
			{
				Locale:      "en-US",
				Name:        "Identity Credential",
				Description: "English description",
				Rendering: &RenderingMetadata{
					Simple: &SimpleRendering{
						Logo: &LogoMetadata{
							URI:     "https://example.com/logo.png",
							AltText: "Example Logo",
						},
						BackgroundColor: "#FFFFFF",
						TextColor:       "#000000",
					},
				},
			},
			{
				Locale:      "de-DE",
				Name:        "Identitatsnachweis",
				Description: "German description",
			},
		},
		Claims: []ClaimMetadata{
			{
				Path:      NewClaimPath("given_name"),
				SD:        SDAlways,
				Mandatory: true,
			},
			{
				Path: NewClaimPath("family_name"),
				SD:   SDAlways,
			},
			{
				Path: NewClaimPath("address"),
				SD:   SDAllowed,
			},
			{
				Path: NewClaimPath("address", "country"),
				SD:   SDNever,
			},
			{
				Path: NewClaimPath("nationalities", nil), // Wildcard for array elements
				SD:   SDAlways,
			},
		},
	}

	if metadata.VCT != "https://example.com/credentials/IdentityCredential" {
		t.Errorf("VCT = %q", metadata.VCT)
	}
	if metadata.Name != "Identity Credential" {
		t.Errorf("Name = %q", metadata.Name)
	}
	if len(metadata.Display) != 2 {
		t.Errorf("Display count = %d, want 2", len(metadata.Display))
	}
	if len(metadata.Claims) != 5 {
		t.Errorf("Claims count = %d, want 5", len(metadata.Claims))
	}

	// Test rendering metadata
	if metadata.Display[0].Rendering == nil {
		t.Error("Rendering should not be nil")
	}
	if metadata.Display[0].Rendering.Simple == nil {
		t.Error("Simple rendering should not be nil")
	}
	if metadata.Display[0].Rendering.Simple.Logo.URI != "https://example.com/logo.png" {
		t.Error("Logo URI mismatch")
	}

	// Test claim path with wildcard
	if metadata.Claims[4].Path.String() != "nationalities.*" {
		t.Errorf("Claim path = %q, want 'nationalities.*'", metadata.Claims[4].Path.String())
	}
}

func TestClaimPath(t *testing.T) {
	t.Run("simple path", func(t *testing.T) {
		path := NewClaimPath("given_name")
		if path.String() != "given_name" {
			t.Errorf("String() = %q, want 'given_name'", path.String())
		}
	})

	t.Run("nested path", func(t *testing.T) {
		path := NewClaimPath("address", "street_address")
		if path.String() != "address.street_address" {
			t.Errorf("String() = %q, want 'address.street_address'", path.String())
		}
	})

	t.Run("array index path", func(t *testing.T) {
		path := NewClaimPath("nationalities", 0)
		if path.String() != "nationalities.[0]" {
			t.Errorf("String() = %q, want 'nationalities.[0]'", path.String())
		}
	})

	t.Run("wildcard path", func(t *testing.T) {
		path := NewClaimPath("nationalities", nil)
		if path.String() != "nationalities.*" {
			t.Errorf("String() = %q, want 'nationalities.*'", path.String())
		}
	})

	t.Run("complex nested path", func(t *testing.T) {
		path := NewClaimPath("address", "lines", 0)
		if path.String() != "address.lines.[0]" {
			t.Errorf("String() = %q, want 'address.lines.[0]'", path.String())
		}
	})

	t.Run("empty path", func(t *testing.T) {
		path := NewClaimPath()
		if path.String() != "" {
			t.Errorf("String() = %q, want ''", path.String())
		}
	})

	t.Run("JSON marshaling", func(t *testing.T) {
		path := NewClaimPath("address", "street_address")
		data, err := json.Marshal(path)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if string(data) != `["address","street_address"]` {
			t.Errorf("JSON = %s, want [\"address\",\"street_address\"]", data)
		}
	})
}

func TestVCPayload(t *testing.T) {
	now := time.Now().Unix()
	exp := time.Now().Add(time.Hour).Unix()

	payload := VCPayload{
		Issuer:         "https://issuer.example.com",
		Subject:        "user:12345",
		IssuedAt:       now,
		ExpirationTime: exp,
		VCT:            "https://example.com/credentials/IdentityCredential",
		VCTIntegrity:   "sha256-abcdef",
		Status: &VCStatus{
			StatusList: &StatusListReference{
				Index: 42,
				URI:   "https://issuer.example.com/status/1",
			},
		},
	}

	if payload.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %q", payload.Issuer)
	}
	if payload.VCTIntegrity != "sha256-abcdef" {
		t.Errorf("VCTIntegrity = %q", payload.VCTIntegrity)
	}
	if payload.Status == nil {
		t.Fatal("Status is nil")
	}
	if payload.Status.StatusList == nil {
		t.Fatal("StatusList is nil")
	}
	if payload.Status.StatusList.Index != 42 {
		t.Errorf("StatusList.Index = %d, want 42", payload.Status.StatusList.Index)
	}
}

func TestConstants(t *testing.T) {
	// Test MediaType per Section 3.1
	if MediaType != "application/dc+sd-jwt" {
		t.Errorf("MediaType = %q, want 'application/dc+sd-jwt'", MediaType)
	}

	// Test TypeHeader per Section 3.2.1
	if TypeHeader != "dc+sd-jwt" {
		t.Errorf("TypeHeader = %q, want 'dc+sd-jwt'", TypeHeader)
	}
}

func TestSelectiveDisclosureMode(t *testing.T) {
	if SDAlways != "always" {
		t.Errorf("SDAlways = %q, want 'always'", SDAlways)
	}
	if SDAllowed != "allowed" {
		t.Errorf("SDAllowed = %q, want 'allowed'", SDAllowed)
	}
	if SDNever != "never" {
		t.Errorf("SDNever = %q, want 'never'", SDNever)
	}
}

func TestDisplayMetadata(t *testing.T) {
	display := DisplayMetadata{
		Locale:      "en-US",
		Name:        "Test Credential",
		Description: "A test credential",
		Rendering: &RenderingMetadata{
			Simple: &SimpleRendering{
				Logo: &LogoMetadata{
					URI:          "https://example.com/logo.png",
					URIIntegrity: "sha256-abc123",
					AltText:      "Logo",
				},
				BackgroundImage: &BackgroundImageMetadata{
					URI:          "https://example.com/background.png",
					URIIntegrity: "sha256-bg123",
				},
				BackgroundColor: "#FFFFFF",
				TextColor:       "#000000",
			},
			SVGTemplates: []SVGTemplate{
				{
					URI:          "https://example.com/template.svg",
					URIIntegrity: "sha256-def456",
					Properties: map[string]any{
						"orientation": "portrait",
					},
				},
			},
		},
	}

	if display.Locale != "en-US" {
		t.Errorf("Locale = %q, want 'en-US'", display.Locale)
	}
	if display.Rendering.Simple.Logo.URIIntegrity != "sha256-abc123" {
		t.Errorf("Logo URIIntegrity = %q", display.Rendering.Simple.Logo.URIIntegrity)
	}
	if len(display.Rendering.SVGTemplates) != 1 {
		t.Errorf("SVGTemplates count = %d, want 1", len(display.Rendering.SVGTemplates))
	}
}

func TestClaimMetadata(t *testing.T) {
	claim := ClaimMetadata{
		Path:      NewClaimPath("given_name"),
		Mandatory: true,
		SD:        SDAlways,
		SVGID:     "given_name_field",
		Display: []DisplayMetadata{
			{
				Locale: "en-US",
				Label:  "Given Name",
			},
		},
	}

	if !claim.Mandatory {
		t.Error("Mandatory should be true")
	}
	if claim.SD != SDAlways {
		t.Errorf("SD = %q, want 'always'", claim.SD)
	}
	if claim.SVGID != "given_name_field" {
		t.Errorf("SVGID = %q", claim.SVGID)
	}
	if len(claim.Display) != 1 {
		t.Errorf("Display count = %d, want 1", len(claim.Display))
	}
}

func TestValidateVCIntegrityMetadata(t *testing.T) {
	payload := map[string]any{
		"vct":            "https://example.com/credentials/Test",
		"vct#integrity":  "sha256-abc123==",
		"given_name":     "Jane",
		"family_name":    "Doe",
		"credential_age": 42,
	}

	if err := ValidateVC(payload); err != nil {
		t.Fatalf("ValidateVC() error = %v", err)
	}

	payload["vct#integrity"] = "invalid-integrity"
	if err := ValidateVC(payload); err == nil {
		t.Error("ValidateVC() should fail with invalid vct#integrity")
	}
}

func TestValidateVCStatusClaim(t *testing.T) {
	payload := map[string]any{
		"vct":    "https://example.com/credentials/Test",
		"status": "invalid",
	}
	if err := ValidateVC(payload); err == nil {
		t.Error("ValidateVC() should fail with invalid status claim")
	}
}

func TestValidateVCTMetadata(t *testing.T) {
	metadata := &VCTMetadata{
		VCT: "https://example.com/credentials/Test",
		Display: []DisplayMetadata{
			{
				Locale: "en-US",
				Name:   "Test Credential",
			},
		},
		Claims: []ClaimMetadata{
			{
				Path: NewClaimPath("given_name"),
				Display: []DisplayMetadata{
					{
						Locale: "en-US",
						Label:  "Given Name",
					},
				},
			},
		},
	}

	if err := ValidateVCTMetadata(metadata); err != nil {
		t.Fatalf("ValidateVCTMetadata() error = %v", err)
	}

	metadata.Display[0].Locale = ""
	if err := ValidateVCTMetadata(metadata); err == nil {
		t.Error("ValidateVCTMetadata() should fail when display locale is missing")
	}
}

func TestValidateClaimPath(t *testing.T) {
	if err := ValidateClaimPath(ClaimPath{}); err == nil {
		t.Error("ValidateClaimPath() should fail for empty path")
	}
	if err := ValidateClaimPath(NewClaimPath("claims", -1)); err == nil {
		t.Error("ValidateClaimPath() should fail for negative index")
	}
	if err := ValidateClaimPath(NewClaimPath("claims", 0)); err != nil {
		t.Fatalf("ValidateClaimPath() error = %v", err)
	}
}
