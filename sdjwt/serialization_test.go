package sdjwt

import (
	"strings"
	"testing"
)

func TestSerialize(t *testing.T) {
	t.Run("SD-JWT without disclosures", func(t *testing.T) {
		sdj := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.abc",
			Disclosures:     nil,
			HashAlgorithm:   HashAlgSHA256,
		}

		serialized := sdj.Serialize()

		// Should end with ~
		if !strings.HasSuffix(serialized, Separator) {
			t.Error("Serialized should end with separator")
		}

		// Should have exactly 2 parts (JWT and empty)
		parts := strings.Split(serialized, Separator)
		if len(parts) != 2 {
			t.Errorf("Parts count = %d, want 2", len(parts))
		}

		// Last part should be empty
		if parts[len(parts)-1] != "" {
			t.Error("Last part should be empty")
		}
	})

	t.Run("SD-JWT with disclosures", func(t *testing.T) {
		d1, _ := NewDisclosureWithSalt("salt1", "name", "John", HashAlgSHA256)
		d2, _ := NewDisclosureWithSalt("salt2", "age", 30, HashAlgSHA256)

		sdj := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d1, *d2},
			HashAlgorithm:   HashAlgSHA256,
		}

		serialized := sdj.Serialize()

		// Should end with ~
		if !strings.HasSuffix(serialized, Separator) {
			t.Error("Serialized should end with separator")
		}

		// Should contain disclosures
		if !strings.Contains(serialized, d1.Encoded) {
			t.Error("Should contain first disclosure")
		}
		if !strings.Contains(serialized, d2.Encoded) {
			t.Error("Should contain second disclosure")
		}

		// Format: JWT~D1~D2~
		parts := strings.Split(serialized, Separator)
		if len(parts) != 4 { // JWT, D1, D2, empty
			t.Errorf("Parts count = %d, want 4", len(parts))
		}
	})
}

func TestSerializeWithKB(t *testing.T) {
	d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)

	sdjwtKB := &SDJWTWithKB{
		SDJWT: SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d},
			HashAlgorithm:   HashAlgSHA256,
		},
		KeyBindingJWT: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUifQ.sig",
	}

	serialized := sdjwtKB.Serialize()

	// Should NOT end with ~ (KB-JWT is at the end)
	if strings.HasSuffix(serialized, Separator) {
		t.Error("Serialized with KB should not end with separator")
	}

	// Should contain KB-JWT
	if !strings.HasSuffix(serialized, sdjwtKB.KeyBindingJWT) {
		t.Error("Should end with KB-JWT")
	}

	// Format: JWT~D1~KB-JWT
	parts := strings.Split(serialized, Separator)
	if len(parts) != 3 {
		t.Errorf("Parts count = %d, want 3", len(parts))
	}
}

func TestParse(t *testing.T) {
	t.Run("parse SD-JWT without disclosures", func(t *testing.T) {
		input := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.abc~"

		sdj, kbJWT, err := Parse(input, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		if kbJWT != "" {
			t.Error("KB-JWT should be empty")
		}

		if len(sdj.Disclosures) != 0 {
			t.Errorf("Disclosures count = %d, want 0", len(sdj.Disclosures))
		}
	})

	t.Run("parse SD-JWT with disclosures", func(t *testing.T) {
		// Create test disclosures
		d1, _ := NewDisclosureWithSalt("2GLC42sKQveCfGfryNRN9w", "family_name", "Doe", HashAlgSHA256)
		d2, _ := NewDisclosureWithSalt("eluV5Og3gSNII8EYnsxA_A", "given_name", "John", HashAlgSHA256)

		input := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz~" + d1.Encoded + "~" + d2.Encoded + "~"

		sdj, kbJWT, err := Parse(input, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		if kbJWT != "" {
			t.Error("KB-JWT should be empty")
		}

		if len(sdj.Disclosures) != 2 {
			t.Errorf("Disclosures count = %d, want 2", len(sdj.Disclosures))
		}

		// Verify disclosures are parsed correctly
		if sdj.Disclosures[0].ClaimName != "family_name" {
			t.Errorf("First disclosure claim name = %q, want family_name", sdj.Disclosures[0].ClaimName)
		}
		if sdj.Disclosures[1].ClaimName != "given_name" {
			t.Errorf("Second disclosure claim name = %q, want given_name", sdj.Disclosures[1].ClaimName)
		}
	})

	t.Run("parse SD-JWT+KB", func(t *testing.T) {
		d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)
		kbJWTStr := "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyIn0.sig"

		input := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz~" + d.Encoded + "~" + kbJWTStr

		sdj, kbJWT, err := Parse(input, HashAlgSHA256)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		if kbJWT != kbJWTStr {
			t.Errorf("KB-JWT = %q, want %q", kbJWT, kbJWTStr)
		}

		if len(sdj.Disclosures) != 1 {
			t.Errorf("Disclosures count = %d, want 1", len(sdj.Disclosures))
		}
	})

	t.Run("reject SD-JWT without trailing separator", func(t *testing.T) {
		input := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.abc"
		_, _, err := Parse(input, HashAlgSHA256)
		if err == nil {
			t.Fatal("Parse() should fail without trailing separator for SD-JWT")
		}
	})
}

func TestParseSDJWT(t *testing.T) {
	d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)
	input := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz~" + d.Encoded + "~"

	sdj, err := ParseSDJWT(input, HashAlgSHA256)
	if err != nil {
		t.Fatalf("ParseSDJWT() error = %v", err)
	}

	if len(sdj.Disclosures) != 1 {
		t.Errorf("Disclosures count = %d, want 1", len(sdj.Disclosures))
	}

	// Should fail if KB-JWT is present
	kbInput := input[:len(input)-1] + "eyJhbGciOiJFUzI1NiJ9.eyJ0eXAiOiJrYitqd3QifQ.abc"
	_, err = ParseSDJWT(kbInput, HashAlgSHA256)
	if err == nil {
		t.Error("ParseSDJWT should fail when KB-JWT is present")
	}
}

func TestParseSDJWTWithKB(t *testing.T) {
	d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)
	kbJWTStr := "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJ2ZXJpZmllciJ9.sig"
	input := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz~" + d.Encoded + "~" + kbJWTStr

	sdjwtKB, err := ParseSDJWTWithKB(input, HashAlgSHA256)
	if err != nil {
		t.Fatalf("ParseSDJWTWithKB() error = %v", err)
	}

	if sdjwtKB.KeyBindingJWT != kbJWTStr {
		t.Errorf("KB-JWT = %q, want %q", sdjwtKB.KeyBindingJWT, kbJWTStr)
	}

	// Should fail if KB-JWT is not present
	noKBInput := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz~" + d.Encoded + "~"
	_, err = ParseSDJWTWithKB(noKBInput, HashAlgSHA256)
	if err == nil {
		t.Error("ParseSDJWTWithKB should fail when KB-JWT is not present")
	}
}

func TestRoundTrip(t *testing.T) {
	t.Run("SD-JWT round trip", func(t *testing.T) {
		d1, _ := NewDisclosure("family_name", "Doe", HashAlgSHA256)
		d2, _ := NewDisclosure("given_name", "John", HashAlgSHA256)

		original := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIiwiZGVmIl19.xyz",
			Disclosures:     []Disclosure{*d1, *d2},
			HashAlgorithm:   HashAlgSHA256,
		}

		serialized := original.Serialize()
		parsed, err := ParseSDJWT(serialized, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseSDJWT() error = %v", err)
		}

		if parsed.IssuerSignedJWT != original.IssuerSignedJWT {
			t.Error("IssuerSignedJWT mismatch")
		}

		if len(parsed.Disclosures) != len(original.Disclosures) {
			t.Errorf("Disclosures count = %d, want %d", len(parsed.Disclosures), len(original.Disclosures))
		}

		// Verify disclosures match (order may differ)
		disclosureDigests := make(map[string]bool)
		for _, d := range original.Disclosures {
			disclosureDigests[d.Digest] = true
		}
		for _, d := range parsed.Disclosures {
			if !disclosureDigests[d.Digest] {
				t.Errorf("Unexpected disclosure digest: %s", d.Digest)
			}
		}
	})
}

func TestFindDisclosureByDigest(t *testing.T) {
	d1, _ := NewDisclosure("name1", "value1", HashAlgSHA256)
	d2, _ := NewDisclosure("name2", "value2", HashAlgSHA256)

	sdj := &SDJWT{
		IssuerSignedJWT: "jwt",
		Disclosures:     []Disclosure{*d1, *d2},
	}

	// Find existing
	found := sdj.FindDisclosureByDigest(d1.Digest)
	if found == nil {
		t.Fatal("Should find disclosure")
	}
	if found.ClaimName != "name1" {
		t.Errorf("ClaimName = %q, want name1", found.ClaimName)
	}

	// Find non-existing
	notFound := sdj.FindDisclosureByDigest("nonexistent")
	if notFound != nil {
		t.Error("Should not find non-existent disclosure")
	}
}

func TestSelectDisclosures(t *testing.T) {
	d1, _ := NewDisclosure("name1", "value1", HashAlgSHA256)
	d2, _ := NewDisclosure("name2", "value2", HashAlgSHA256)
	d3, _ := NewDisclosure("name3", "value3", HashAlgSHA256)

	sdj := &SDJWT{
		IssuerSignedJWT: "jwt",
		Disclosures:     []Disclosure{*d1, *d2, *d3},
		HashAlgorithm:   HashAlgSHA256,
	}

	selected := sdj.SelectDisclosures(map[string]bool{
		d1.Digest: true,
		d3.Digest: true,
	})

	if len(selected.Disclosures) != 2 {
		t.Fatalf("Selected disclosures count = %d, want 2", len(selected.Disclosures))
	}

	// Verify correct disclosures were selected
	digests := make(map[string]bool)
	for _, d := range selected.Disclosures {
		digests[d.Digest] = true
	}

	if !digests[d1.Digest] || !digests[d3.Digest] {
		t.Error("Wrong disclosures selected")
	}
	if digests[d2.Digest] {
		t.Error("d2 should not be selected")
	}

	// Verify JWT is preserved
	if selected.IssuerSignedJWT != sdj.IssuerSignedJWT {
		t.Error("IssuerSignedJWT should be preserved")
	}
}

func TestFlattenJSON(t *testing.T) {
	t.Run("SD-JWT to FlattenJSON", func(t *testing.T) {
		d1, _ := NewDisclosureWithSalt("salt1", "name", "John", HashAlgSHA256)
		d2, _ := NewDisclosureWithSalt("salt2", "age", 30, HashAlgSHA256)

		sdj := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d1, *d2},
			HashAlgorithm:   HashAlgSHA256,
		}

		flat, err := sdj.ToFlattenJSON()
		if err != nil {
			t.Fatalf("ToFlattenJSON() error = %v", err)
		}

		if flat.Protected != "eyJhbGciOiJFUzI1NiJ9" {
			t.Errorf("Protected = %q, want eyJhbGciOiJFUzI1NiJ9", flat.Protected)
		}
		if flat.Payload != "eyJfc2QiOlsiYWJjIl19" {
			t.Errorf("Payload = %q, want eyJfc2QiOlsiYWJjIl19", flat.Payload)
		}
		if flat.Signature != "xyz" {
			t.Errorf("Signature = %q, want xyz", flat.Signature)
		}
		if flat.Header == nil || len(flat.Header.Disclosures) != 2 {
			t.Errorf("Disclosures count = %v, want 2", flat.Header)
		}
		if flat.Header != nil && flat.Header.KBJwt != "" {
			t.Error("KBJwt should be empty")
		}
	})

	t.Run("SD-JWT+KB to FlattenJSON", func(t *testing.T) {
		d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)

		sdjwtKB := &SDJWTWithKB{
			SDJWT: SDJWT{
				IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
				Disclosures:     []Disclosure{*d},
				HashAlgorithm:   HashAlgSHA256,
			},
			KeyBindingJWT: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJ2ZXJpZmllciJ9.sig",
		}

		flat, err := sdjwtKB.ToFlattenJSON()
		if err != nil {
			t.Fatalf("ToFlattenJSON() error = %v", err)
		}

		if flat.Header == nil || flat.Header.KBJwt == "" {
			t.Fatal("KBJwt should be present")
		}
	})

	t.Run("FlattenJSON round trip", func(t *testing.T) {
		d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)

		original := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d},
			HashAlgorithm:   HashAlgSHA256,
		}

		// Serialize to JSON
		jsonStr, err := original.SerializeFlattenJSON()
		if err != nil {
			t.Fatalf("SerializeFlattenJSON() error = %v", err)
		}

		// Parse back
		parsed, kbJWT, err := ParseFlattenJSON(jsonStr, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseFlattenJSON() error = %v", err)
		}

		if kbJWT != "" {
			t.Error("kbJWT should be empty")
		}
		if parsed.IssuerSignedJWT != original.IssuerSignedJWT {
			t.Errorf("IssuerSignedJWT = %q, want %q", parsed.IssuerSignedJWT, original.IssuerSignedJWT)
		}
		if len(parsed.Disclosures) != len(original.Disclosures) {
			t.Errorf("Disclosures count = %d, want %d", len(parsed.Disclosures), len(original.Disclosures))
		}
	})
}

func TestGeneralJSON(t *testing.T) {
	t.Run("SD-JWT to GeneralJSON", func(t *testing.T) {
		d1, _ := NewDisclosureWithSalt("salt1", "name", "John", HashAlgSHA256)
		d2, _ := NewDisclosureWithSalt("salt2", "age", 30, HashAlgSHA256)

		sdj := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d1, *d2},
			HashAlgorithm:   HashAlgSHA256,
		}

		general, err := sdj.ToGeneralJSON()
		if err != nil {
			t.Fatalf("ToGeneralJSON() error = %v", err)
		}

		if general.Payload != "eyJfc2QiOlsiYWJjIl19" {
			t.Errorf("Payload = %q, want eyJfc2QiOlsiYWJjIl19", general.Payload)
		}
		if len(general.Signatures) != 1 {
			t.Fatalf("Signatures count = %d, want 1", len(general.Signatures))
		}
		if general.Signatures[0].Protected != "eyJhbGciOiJFUzI1NiJ9" {
			t.Errorf("Signatures[0].Protected = %q, want eyJhbGciOiJFUzI1NiJ9", general.Signatures[0].Protected)
		}
		if general.Signatures[0].Signature != "xyz" {
			t.Errorf("Signatures[0].Signature = %q, want xyz", general.Signatures[0].Signature)
		}
		if general.Signatures[0].Header == nil || len(general.Signatures[0].Header.Disclosures) != 2 {
			t.Errorf("Disclosures count = %v, want 2", general.Signatures[0].Header)
		}
	})

	t.Run("SD-JWT+KB to GeneralJSON", func(t *testing.T) {
		d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)

		sdjwtKB := &SDJWTWithKB{
			SDJWT: SDJWT{
				IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
				Disclosures:     []Disclosure{*d},
				HashAlgorithm:   HashAlgSHA256,
			},
			KeyBindingJWT: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJ2ZXJpZmllciJ9.sig",
		}

		general, err := sdjwtKB.ToGeneralJSON()
		if err != nil {
			t.Fatalf("ToGeneralJSON() error = %v", err)
		}

		if general.Signatures[0].Header == nil || general.Signatures[0].Header.KBJwt == "" {
			t.Fatal("KBJwt should be present")
		}
	})

	t.Run("GeneralJSON round trip", func(t *testing.T) {
		d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)

		original := &SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d},
			HashAlgorithm:   HashAlgSHA256,
		}

		// Serialize to JSON
		jsonStr, err := original.SerializeGeneralJSON()
		if err != nil {
			t.Fatalf("SerializeGeneralJSON() error = %v", err)
		}

		// Parse back
		parsed, kbJWT, err := ParseGeneralJSON(jsonStr, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseGeneralJSON() error = %v", err)
		}

		if kbJWT != "" {
			t.Error("kbJWT should be empty")
		}
		if parsed.IssuerSignedJWT != original.IssuerSignedJWT {
			t.Errorf("IssuerSignedJWT = %q, want %q", parsed.IssuerSignedJWT, original.IssuerSignedJWT)
		}
		if len(parsed.Disclosures) != len(original.Disclosures) {
			t.Errorf("Disclosures count = %d, want %d", len(parsed.Disclosures), len(original.Disclosures))
		}
	})
}

func TestJSONSerializationWithKB(t *testing.T) {
	d, _ := NewDisclosureWithSalt("salt", "name", "John", HashAlgSHA256)

	original := &SDJWTWithKB{
		SDJWT: SDJWT{
			IssuerSignedJWT: "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.xyz",
			Disclosures:     []Disclosure{*d},
			HashAlgorithm:   HashAlgSHA256,
		},
		KeyBindingJWT: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJ2ZXJpZmllciJ9.sig",
	}

	t.Run("FlattenJSON with KB round trip", func(t *testing.T) {
		jsonStr, err := original.SerializeFlattenJSON()
		if err != nil {
			t.Fatalf("SerializeFlattenJSON() error = %v", err)
		}

		parsed, kbJWT, err := ParseFlattenJSON(jsonStr, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseFlattenJSON() error = %v", err)
		}

		if kbJWT != original.KeyBindingJWT {
			t.Errorf("kbJWT = %q, want %q", kbJWT, original.KeyBindingJWT)
		}
		if parsed.IssuerSignedJWT != original.SDJWT.IssuerSignedJWT {
			t.Errorf("IssuerSignedJWT mismatch")
		}
	})

	t.Run("GeneralJSON with KB round trip", func(t *testing.T) {
		jsonStr, err := original.SerializeGeneralJSON()
		if err != nil {
			t.Fatalf("SerializeGeneralJSON() error = %v", err)
		}

		parsed, kbJWT, err := ParseGeneralJSON(jsonStr, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseGeneralJSON() error = %v", err)
		}

		if kbJWT != original.KeyBindingJWT {
			t.Errorf("kbJWT = %q, want %q", kbJWT, original.KeyBindingJWT)
		}
		if parsed.IssuerSignedJWT != original.SDJWT.IssuerSignedJWT {
			t.Errorf("IssuerSignedJWT mismatch")
		}
	})
}
