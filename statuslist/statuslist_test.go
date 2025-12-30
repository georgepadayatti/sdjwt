package statuslist

import (
	"testing"
)

func TestNewStatusList(t *testing.T) {
	tests := []struct {
		name          string
		size          int
		bitsPerStatus BitsPerStatus
		wantErr       bool
	}{
		{"1-bit status list", 1000, Bits1, false},
		{"2-bit status list", 1000, Bits2, false},
		{"4-bit status list", 1000, Bits4, false},
		{"8-bit status list", 1000, Bits8, false},
		{"invalid size", 0, Bits1, true},
		{"negative size", -1, Bits1, true},
		{"invalid bits per status", 1000, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl, err := NewStatusList(tt.size, tt.bitsPerStatus)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStatusList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if sl.Size() != tt.size {
					t.Errorf("Size() = %d, want %d", sl.Size(), tt.size)
				}
				if sl.BitsPerStatus() != tt.bitsPerStatus {
					t.Errorf("BitsPerStatus() = %d, want %d", sl.BitsPerStatus(), tt.bitsPerStatus)
				}
			}
		})
	}
}

func TestStatusList1Bit(t *testing.T) {
	sl, err := NewStatusList(100, Bits1)
	if err != nil {
		t.Fatalf("NewStatusList() error = %v", err)
	}

	// Initially all should be 0
	for i := 0; i < 100; i++ {
		status, err := sl.GetStatus(i)
		if err != nil {
			t.Fatalf("GetStatus(%d) error = %v", i, err)
		}
		if status != 0 {
			t.Errorf("GetStatus(%d) = %d, want 0", i, status)
		}
	}

	// Set some statuses to 1
	indices := []int{0, 5, 10, 50, 99}
	for _, idx := range indices {
		if err := sl.SetStatus(idx, 1); err != nil {
			t.Fatalf("SetStatus(%d, 1) error = %v", idx, err)
		}
	}

	// Verify
	for i := 0; i < 100; i++ {
		status, err := sl.GetStatus(i)
		if err != nil {
			t.Fatalf("GetStatus(%d) error = %v", i, err)
		}
		expected := 0
		for _, idx := range indices {
			if i == idx {
				expected = 1
				break
			}
		}
		if status != expected {
			t.Errorf("GetStatus(%d) = %d, want %d", i, status, expected)
		}
	}

	// Test setting back to 0
	if err := sl.SetStatus(5, 0); err != nil {
		t.Fatalf("SetStatus(5, 0) error = %v", err)
	}
	status, _ := sl.GetStatus(5)
	if status != 0 {
		t.Errorf("GetStatus(5) = %d, want 0", status)
	}
}

func TestStatusList2Bit(t *testing.T) {
	sl, err := NewStatusList(100, Bits2)
	if err != nil {
		t.Fatalf("NewStatusList() error = %v", err)
	}

	// Test all valid values (0-3)
	for i := 0; i < 4; i++ {
		if err := sl.SetStatus(i, i); err != nil {
			t.Fatalf("SetStatus(%d, %d) error = %v", i, i, err)
		}
	}

	for i := 0; i < 4; i++ {
		status, err := sl.GetStatus(i)
		if err != nil {
			t.Fatalf("GetStatus(%d) error = %v", i, err)
		}
		if status != i {
			t.Errorf("GetStatus(%d) = %d, want %d", i, status, i)
		}
	}

	// Test invalid value
	if err := sl.SetStatus(0, 4); err == nil {
		t.Error("SetStatus(0, 4) should fail for 2-bit status")
	}
}

func TestStatusList4Bit(t *testing.T) {
	sl, err := NewStatusList(100, Bits4)
	if err != nil {
		t.Fatalf("NewStatusList() error = %v", err)
	}

	// Test all valid values (0-15)
	for i := 0; i < 16; i++ {
		if err := sl.SetStatus(i, i); err != nil {
			t.Fatalf("SetStatus(%d, %d) error = %v", i, i, err)
		}
	}

	for i := 0; i < 16; i++ {
		status, err := sl.GetStatus(i)
		if err != nil {
			t.Fatalf("GetStatus(%d) error = %v", i, err)
		}
		if status != i {
			t.Errorf("GetStatus(%d) = %d, want %d", i, status, i)
		}
	}

	// Test invalid value
	if err := sl.SetStatus(0, 16); err == nil {
		t.Error("SetStatus(0, 16) should fail for 4-bit status")
	}
}

func TestStatusList8Bit(t *testing.T) {
	sl, err := NewStatusList(100, Bits8)
	if err != nil {
		t.Fatalf("NewStatusList() error = %v", err)
	}

	// Test some values
	testValues := []int{0, 1, 127, 128, 255}
	for i, v := range testValues {
		if err := sl.SetStatus(i, v); err != nil {
			t.Fatalf("SetStatus(%d, %d) error = %v", i, v, err)
		}
	}

	for i, expected := range testValues {
		status, err := sl.GetStatus(i)
		if err != nil {
			t.Fatalf("GetStatus(%d) error = %v", i, err)
		}
		if status != expected {
			t.Errorf("GetStatus(%d) = %d, want %d", i, status, expected)
		}
	}

	// Test invalid value
	if err := sl.SetStatus(0, 256); err == nil {
		t.Error("SetStatus(0, 256) should fail for 8-bit status")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name          string
		size          int
		bitsPerStatus BitsPerStatus
	}{
		{"1-bit small", 16, Bits1},
		{"1-bit large", 10000, Bits1},
		{"2-bit", 1000, Bits2},
		{"4-bit", 1000, Bits4},
		{"8-bit", 1000, Bits8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create and populate status list
			original, err := NewStatusList(tt.size, tt.bitsPerStatus)
			if err != nil {
				t.Fatalf("NewStatusList() error = %v", err)
			}

			maxValue := (1 << tt.bitsPerStatus) - 1
			for i := 0; i < tt.size; i++ {
				value := i % (maxValue + 1)
				if err := original.SetStatus(i, value); err != nil {
					t.Fatalf("SetStatus(%d, %d) error = %v", i, value, err)
				}
			}

			// Encode
			encoded, err := original.Encode()
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			// Decode
			decoded, err := Decode(encoded, tt.size, tt.bitsPerStatus)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			// Verify
			for i := 0; i < tt.size; i++ {
				originalStatus, _ := original.GetStatus(i)
				decodedStatus, _ := decoded.GetStatus(i)
				if originalStatus != decodedStatus {
					t.Errorf("Status mismatch at index %d: original=%d, decoded=%d", i, originalStatus, decodedStatus)
				}
			}
		})
	}
}

func TestStatusListOutOfRange(t *testing.T) {
	sl, _ := NewStatusList(100, Bits1)

	// Test GetStatus out of range
	_, err := sl.GetStatus(-1)
	if err == nil {
		t.Error("GetStatus(-1) should fail")
	}

	_, err = sl.GetStatus(100)
	if err == nil {
		t.Error("GetStatus(100) should fail")
	}

	// Test SetStatus out of range
	err = sl.SetStatus(-1, 0)
	if err == nil {
		t.Error("SetStatus(-1, 0) should fail")
	}

	err = sl.SetStatus(100, 0)
	if err == nil {
		t.Error("SetStatus(100, 0) should fail")
	}
}

func TestStatusListToken(t *testing.T) {
	// Create a status list
	sl, err := NewStatusList(1000, Bits1)
	if err != nil {
		t.Fatalf("NewStatusList() error = %v", err)
	}

	// Set some statuses as revoked
	revokedIndices := []int{42, 100, 500}
	for _, idx := range revokedIndices {
		if err := sl.SetStatus(idx, StatusInvalid); err != nil {
			t.Fatalf("SetStatus() error = %v", err)
		}
	}

	// Create token
	token, err := NewStatusListToken(
		"https://issuer.example.com",
		"https://issuer.example.com/status/1",
		sl,
		1700000000,
		1700086400,
	)
	if err != nil {
		t.Fatalf("NewStatusListToken() error = %v", err)
	}

	// Verify token fields
	if token.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %q", token.Issuer)
	}
	if token.StatusList.Bits != 1 {
		t.Errorf("StatusList.Bits = %d, want 1", token.StatusList.Bits)
	}
	if token.StatusList.List == "" {
		t.Error("StatusList.List should not be empty")
	}

	// Serialize to JSON
	jsonData, err := token.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Parse back
	parsed, err := ParseStatusListToken(jsonData)
	if err != nil {
		t.Fatalf("ParseStatusListToken() error = %v", err)
	}

	// Get status list from parsed token
	parsedSL, err := parsed.GetStatusList(1000)
	if err != nil {
		t.Fatalf("GetStatusList() error = %v", err)
	}

	// Verify revoked indices
	for _, idx := range revokedIndices {
		status, err := parsedSL.GetStatus(idx)
		if err != nil {
			t.Fatalf("GetStatus(%d) error = %v", idx, err)
		}
		if status != StatusInvalid {
			t.Errorf("GetStatus(%d) = %d, want %d (StatusInvalid)", idx, status, StatusInvalid)
		}
	}

	// Verify non-revoked index
	status, _ := parsedSL.GetStatus(0)
	if status != StatusValid {
		t.Errorf("GetStatus(0) = %d, want %d (StatusValid)", status, StatusValid)
	}
}

func TestStatusReference(t *testing.T) {
	ref := StatusReference{
		StatusListIndex: 42,
		StatusListURI:   "https://issuer.example.com/status/1",
	}

	if ref.StatusListIndex != 42 {
		t.Errorf("StatusListIndex = %d, want 42", ref.StatusListIndex)
	}
	if ref.StatusListURI != "https://issuer.example.com/status/1" {
		t.Errorf("StatusListURI = %q", ref.StatusListURI)
	}
}

func BenchmarkEncode(b *testing.B) {
	sl, _ := NewStatusList(100000, Bits1)
	// Set every 10th entry to revoked
	for i := 0; i < 100000; i += 10 {
		sl.SetStatus(i, 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sl.Encode()
	}
}

func BenchmarkDecode(b *testing.B) {
	sl, _ := NewStatusList(100000, Bits1)
	for i := 0; i < 100000; i += 10 {
		sl.SetStatus(i, 1)
	}
	encoded, _ := sl.Encode()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(encoded, 100000, Bits1)
	}
}
