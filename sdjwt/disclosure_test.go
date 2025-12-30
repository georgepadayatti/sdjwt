package sdjwt

import (
	"encoding/json"
	"testing"
)

func TestNewDisclosure(t *testing.T) {
	tests := []struct {
		name       string
		claimName  string
		claimValue any
	}{
		{"string value", "name", "John"},
		{"number value", "age", 30},
		{"boolean value", "active", true},
		{"null value", "middle_name", nil},
		{"object value", "address", map[string]any{"city": "NYC"}},
		{"array value", "tags", []any{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDisclosure(tt.claimName, tt.claimValue, HashAlgSHA256)
			if err != nil {
				t.Fatalf("NewDisclosure() error = %v", err)
			}

			// Verify fields
			if d.ClaimName != tt.claimName {
				t.Errorf("ClaimName = %q, want %q", d.ClaimName, tt.claimName)
			}

			// Verify salt is generated
			if d.Salt == "" {
				t.Error("Salt should not be empty")
			}

			// Verify salt is proper length (16 bytes = ~22 base64url chars)
			saltBytes, err := Base64URLDecode(d.Salt)
			if err != nil {
				t.Errorf("Salt is not valid base64url: %v", err)
			}
			if len(saltBytes) != SaltLength {
				t.Errorf("Salt length = %d bytes, want %d", len(saltBytes), SaltLength)
			}

			// Verify encoded is not empty
			if d.Encoded == "" {
				t.Error("Encoded should not be empty")
			}

			// Verify digest is not empty
			if d.Digest == "" {
				t.Error("Digest should not be empty")
			}

			// Verify digest length (SHA-256 = 43 base64url chars)
			if len(d.Digest) != 43 {
				t.Errorf("Digest length = %d, want 43", len(d.Digest))
			}

			// Verify it's not an array element
			if d.IsArrayElement() {
				t.Error("Should not be array element")
			}
		})
	}
}

func TestNewArrayElementDisclosure(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"string", "item"},
		{"number", 42},
		{"object", map[string]any{"key": "value"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewArrayElementDisclosure(tt.value, HashAlgSHA256)
			if err != nil {
				t.Fatalf("NewArrayElementDisclosure() error = %v", err)
			}

			// Verify claim name is empty for array elements
			if d.ClaimName != "" {
				t.Errorf("ClaimName = %q, want empty", d.ClaimName)
			}

			// Verify it is an array element
			if !d.IsArrayElement() {
				t.Error("Should be array element")
			}

			// Verify salt is generated
			if d.Salt == "" {
				t.Error("Salt should not be empty")
			}
		})
	}
}

func TestParseDisclosure(t *testing.T) {
	// Test parsing object property disclosure
	t.Run("object property", func(t *testing.T) {
		// Create a disclosure
		original, err := NewDisclosure("family_name", "Doe", HashAlgSHA256)
		if err != nil {
			t.Fatalf("NewDisclosure() error = %v", err)
		}

		// Parse it back
		parsed, err := ParseDisclosure(original.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseDisclosure() error = %v", err)
		}

		// Verify fields match
		if parsed.Salt != original.Salt {
			t.Errorf("Salt = %q, want %q", parsed.Salt, original.Salt)
		}
		if parsed.ClaimName != original.ClaimName {
			t.Errorf("ClaimName = %q, want %q", parsed.ClaimName, original.ClaimName)
		}
		if parsed.ClaimValue != original.ClaimValue {
			t.Errorf("ClaimValue = %v, want %v", parsed.ClaimValue, original.ClaimValue)
		}
		if parsed.Digest != original.Digest {
			t.Errorf("Digest = %q, want %q", parsed.Digest, original.Digest)
		}
	})

	// Test parsing array element disclosure
	t.Run("array element", func(t *testing.T) {
		original, err := NewArrayElementDisclosure("US", HashAlgSHA256)
		if err != nil {
			t.Fatalf("NewArrayElementDisclosure() error = %v", err)
		}

		parsed, err := ParseDisclosure(original.Encoded, HashAlgSHA256)
		if err != nil {
			t.Fatalf("ParseDisclosure() error = %v", err)
		}

		if parsed.Salt != original.Salt {
			t.Errorf("Salt = %q, want %q", parsed.Salt, original.Salt)
		}
		if !parsed.IsArrayElement() {
			t.Error("Should be array element")
		}
		if parsed.ClaimValue != original.ClaimValue {
			t.Errorf("ClaimValue = %v, want %v", parsed.ClaimValue, original.ClaimValue)
		}
	})
}

func TestDisclosureEncoding(t *testing.T) {
	// Test that disclosure encoding matches the expected JSON format
	t.Run("object property encoding", func(t *testing.T) {
		d, err := NewDisclosureWithSalt("_26bc4LT-ac6q2KI6cBW5es", "family_name", "Doe", HashAlgSHA256)
		if err != nil {
			t.Fatalf("NewDisclosureWithSalt() error = %v", err)
		}

		// Decode and verify structure
		decoded, err := Base64URLDecode(d.Encoded)
		if err != nil {
			t.Fatalf("Base64URLDecode() error = %v", err)
		}

		var arr []any
		if err := json.Unmarshal(decoded, &arr); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}

		if len(arr) != 3 {
			t.Fatalf("Array length = %d, want 3", len(arr))
		}

		if arr[0] != "_26bc4LT-ac6q2KI6cBW5es" {
			t.Errorf("Salt = %v, want _26bc4LT-ac6q2KI6cBW5es", arr[0])
		}
		if arr[1] != "family_name" {
			t.Errorf("ClaimName = %v, want family_name", arr[1])
		}
		if arr[2] != "Doe" {
			t.Errorf("ClaimValue = %v, want Doe", arr[2])
		}
	})

	t.Run("array element encoding", func(t *testing.T) {
		d, err := NewArrayElementDisclosureWithSalt("lklxF5jMYlGTPUovMNIvCA", "US", HashAlgSHA256)
		if err != nil {
			t.Fatalf("NewArrayElementDisclosureWithSalt() error = %v", err)
		}

		decoded, err := Base64URLDecode(d.Encoded)
		if err != nil {
			t.Fatalf("Base64URLDecode() error = %v", err)
		}

		var arr []any
		if err := json.Unmarshal(decoded, &arr); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}

		if len(arr) != 2 {
			t.Fatalf("Array length = %d, want 2", len(arr))
		}

		if arr[0] != "lklxF5jMYlGTPUovMNIvCA" {
			t.Errorf("Salt = %v, want lklxF5jMYlGTPUovMNIvCA", arr[0])
		}
		if arr[1] != "US" {
			t.Errorf("Value = %v, want US", arr[1])
		}
	})
}

func TestValidateDisclosureClaimName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid name", "family_name", false},
		{"valid with numbers", "claim123", false},
		{"reserved _sd", "_sd", true},
		{"reserved ...", "...", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDisclosureClaimName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDisclosureClaimName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestGenerateDecoyDigest(t *testing.T) {
	algorithms := []string{HashAlgSHA256, HashAlgSHA384, HashAlgSHA512}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			decoy1, err := GenerateDecoyDigest(alg)
			if err != nil {
				t.Fatalf("GenerateDecoyDigest() error = %v", err)
			}

			decoy2, err := GenerateDecoyDigest(alg)
			if err != nil {
				t.Fatalf("GenerateDecoyDigest() error = %v", err)
			}

			// Decoys should be different (random)
			if decoy1 == decoy2 {
				t.Error("Decoys should be different")
			}

			// Verify length based on algorithm
			expectedLen := map[string]int{
				HashAlgSHA256: 43,
				HashAlgSHA384: 64,
				HashAlgSHA512: 86,
			}

			if len(decoy1) != expectedLen[alg] {
				t.Errorf("Decoy length = %d, want %d", len(decoy1), expectedLen[alg])
			}
		})
	}
}
