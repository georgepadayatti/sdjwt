package sdjwt

import (
	"testing"
)

func TestHashDisclosure(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		algorithm string
		wantLen   int // Expected length of base64url encoded hash
	}{
		{
			name:      "SHA-256 empty string",
			input:     "",
			algorithm: HashAlgSHA256,
			wantLen:   43, // 256 bits = 32 bytes = 43 base64url chars (no padding)
		},
		{
			name:      "SHA-256 with content",
			input:     "WyJfc3JUbXN0RDhoMFpIdmlYSTNiYjBnIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ",
			algorithm: HashAlgSHA256,
			wantLen:   43,
		},
		{
			name:      "SHA-384 with content",
			input:     "WyJfc3JUbXN0RDhoMFpIdmlYSTNiYjBnIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ",
			algorithm: HashAlgSHA384,
			wantLen:   64, // 384 bits = 48 bytes = 64 base64url chars
		},
		{
			name:      "SHA-512 with content",
			input:     "WyJfc3JUbXN0RDhoMFpIdmlYSTNiYjBnIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ",
			algorithm: HashAlgSHA512,
			wantLen:   86, // 512 bits = 64 bytes = 86 base64url chars
		},
		{
			name:      "Default algorithm (empty)",
			input:     "test",
			algorithm: "",
			wantLen:   43, // Should default to SHA-256
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashDisclosure(tt.input, tt.algorithm)
			if err != nil {
				t.Errorf("HashDisclosure() error = %v", err)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("HashDisclosure() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestHashDisclosureUnsupported(t *testing.T) {
	_, err := HashDisclosure("test", "sha-1")
	if err == nil {
		t.Error("HashDisclosure() expected error for unsupported algorithm")
	}
}

func TestHashSDJWT(t *testing.T) {
	input := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiMTIzIl19.abc~WyJzYWx0IiwibmFtZSIsIkpvaG4iXQ~"

	tests := []struct {
		algorithm string
		wantLen   int
	}{
		{HashAlgSHA256, 43},
		{HashAlgSHA384, 64},
		{HashAlgSHA512, 86},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got, err := HashSDJWT(input, tt.algorithm)
			if err != nil {
				t.Errorf("HashSDJWT() error = %v", err)
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("HashSDJWT() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestIsSupportedHashAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		{HashAlgSHA256, true},
		{HashAlgSHA384, true},
		{HashAlgSHA512, true},
		{"", true}, // Empty defaults to sha-256
		{"sha-1", false},
		{"md5", false},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			if got := IsSupportedHashAlgorithm(tt.algorithm); got != tt.want {
				t.Errorf("IsSupportedHashAlgorithm(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestBase64URLEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("hello world")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"json", []byte(`["salt","name","John"]`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base64URLEncode(tt.input)
			decoded, err := Base64URLDecode(encoded)
			if err != nil {
				t.Errorf("Base64URLDecode() error = %v", err)
				return
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.input)
			}
		})
	}
}
