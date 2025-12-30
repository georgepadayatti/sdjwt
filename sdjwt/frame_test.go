package sdjwt

import (
	"reflect"
	"sort"
	"testing"
)

func TestNewDisclosureFrame(t *testing.T) {
	frame := NewDisclosureFrame("given_name", "family_name", "email")

	if len(frame.SD) != 3 {
		t.Errorf("SD count = %d, want 3", len(frame.SD))
	}

	if !frame.HasSD("given_name") {
		t.Error("Should have given_name in SD")
	}
	if !frame.HasSD("family_name") {
		t.Error("Should have family_name in SD")
	}
	if frame.HasSD("birthdate") {
		t.Error("Should not have birthdate in SD")
	}
}

func TestDisclosureFrameWithDecoys(t *testing.T) {
	frame := NewDisclosureFrame("name").WithDecoys(3)

	if frame.SDDecoy != 3 {
		t.Errorf("SDDecoy = %d, want 3", frame.SDDecoy)
	}
}

func TestDisclosureFrameWithNested(t *testing.T) {
	addressFrame := NewDisclosureFrame("street", "city")
	frame := NewDisclosureFrame("name").WithNested("address", addressFrame)

	nested := frame.GetNested("address")
	if nested == nil {
		t.Fatal("Nested frame should not be nil")
	}
	if !nested.HasSD("street") {
		t.Error("Nested frame should have street in SD")
	}
	if frame.GetNested("other") != nil {
		t.Error("GetNested should return nil for non-existent key")
	}
}

func TestNewPresentationFrame(t *testing.T) {
	frame := NewPresentationFrame("given_name", "email")

	if !frame.ShouldInclude("given_name") {
		t.Error("Should include given_name")
	}
	if !frame.ShouldInclude("email") {
		t.Error("Should include email")
	}
	if frame.ShouldInclude("family_name") {
		t.Error("Should not include family_name")
	}
}

func TestPresentationFrameAddClaim(t *testing.T) {
	frame := NewPresentationFrame("name").AddClaim("email").AddClaim("birthdate")

	if !frame.ShouldInclude("name") {
		t.Error("Should include name")
	}
	if !frame.ShouldInclude("email") {
		t.Error("Should include email")
	}
	if !frame.ShouldInclude("birthdate") {
		t.Error("Should include birthdate")
	}
}

func TestPresentationFrameWithNested(t *testing.T) {
	addressFrame := NewPresentationFrame("city", "country")
	frame := NewPresentationFrame("name").WithNested("address", addressFrame)

	nested := frame.GetNested("address")
	if nested == nil {
		t.Fatal("Nested frame should not be nil")
	}
	if !nested.ShouldInclude("city") {
		t.Error("Nested frame should include city")
	}
}

func TestAllDisclosures(t *testing.T) {
	frame := AllDisclosures()
	if frame != nil {
		t.Error("AllDisclosures should return nil")
	}
}

func TestMergeDisclosureFrames(t *testing.T) {
	frame1 := NewDisclosureFrame("name", "email").WithDecoys(2)
	frame2 := NewDisclosureFrame("email", "age").WithDecoys(3)

	merged := MergeDisclosureFrames(frame1, frame2)

	// Should have all unique claims
	if len(merged.SD) != 3 {
		t.Errorf("Merged SD count = %d, want 3", len(merged.SD))
	}

	if !merged.HasSD("name") || !merged.HasSD("email") || !merged.HasSD("age") {
		t.Error("Merged frame should have all claims")
	}

	// Should take max decoys
	if merged.SDDecoy != 3 {
		t.Errorf("Merged SDDecoy = %d, want 3", merged.SDDecoy)
	}
}

func TestMergeDisclosureFramesWithNested(t *testing.T) {
	nested1 := NewDisclosureFrame("street")
	nested2 := NewDisclosureFrame("city")
	frame1 := NewDisclosureFrame("name").WithNested("address", nested1)
	frame2 := NewDisclosureFrame("email").WithNested("address", nested2)

	merged := MergeDisclosureFrames(frame1, frame2)

	// Nested should have both street and city
	nestedMerged := merged.GetNested("address")
	if nestedMerged == nil {
		t.Fatal("Merged nested frame should not be nil")
	}
	if !nestedMerged.HasSD("street") || !nestedMerged.HasSD("city") {
		t.Error("Merged nested frame should have both street and city")
	}
}

func TestMergePresentationFrames(t *testing.T) {
	frame1 := NewPresentationFrame("name", "email")
	frame2 := NewPresentationFrame("email", "age")

	merged := MergePresentationFrames(frame1, frame2)

	if !merged.ShouldInclude("name") || !merged.ShouldInclude("email") || !merged.ShouldInclude("age") {
		t.Error("Merged frame should include all claims")
	}
}

func TestDisclosureFrameFromMap(t *testing.T) {
	m := map[string]any{
		"_sd":       []any{"given_name", "family_name"},
		"_sd_decoy": 2,
		"address": map[string]any{
			"_sd": []any{"street"},
		},
	}

	frame := DisclosureFrameFromMap(m)

	if !frame.HasSD("given_name") {
		t.Error("Frame should have given_name in SD")
	}
	if !frame.HasSD("family_name") {
		t.Error("Frame should have family_name in SD")
	}
	if frame.SDDecoy != 2 {
		t.Errorf("SDDecoy = %d, want 2", frame.SDDecoy)
	}

	nested := frame.GetNested("address")
	if nested == nil {
		t.Fatal("Nested frame should not be nil")
	}
	if !nested.HasSD("street") {
		t.Error("Nested frame should have street in SD")
	}
}

func TestDisclosureFrameFromMapWithFloatDecoy(t *testing.T) {
	m := map[string]any{
		"_sd":       []any{"name"},
		"_sd_decoy": 3.0, // JSON numbers are float64
	}

	frame := DisclosureFrameFromMap(m)

	if frame.SDDecoy != 3 {
		t.Errorf("SDDecoy = %d, want 3", frame.SDDecoy)
	}
}

func TestPresentationFrameFromMap(t *testing.T) {
	m := map[string]any{
		"given_name":  true,
		"family_name": true,
		"address": map[string]any{
			"city":    true,
			"country": true,
		},
	}

	frame := PresentationFrameFromMap(m)

	if !frame.ShouldInclude("given_name") {
		t.Error("Frame should include given_name")
	}
	if !frame.ShouldInclude("family_name") {
		t.Error("Frame should include family_name")
	}

	nested := frame.GetNested("address")
	if nested == nil {
		t.Fatal("Nested frame should not be nil")
	}
	if !nested.ShouldInclude("city") || !nested.ShouldInclude("country") {
		t.Error("Nested frame should include city and country")
	}
}

func TestDisclosureFrameToMap(t *testing.T) {
	frame := NewDisclosureFrame("name", "email").WithDecoys(2)
	frame.WithNested("address", NewDisclosureFrame("street"))

	m := frame.ToMap()

	// Check _sd
	sd, ok := m["_sd"].([]string)
	if !ok {
		t.Fatal("_sd should be []string")
	}
	sort.Strings(sd)
	expected := []string{"email", "name"}
	sort.Strings(expected)
	if !reflect.DeepEqual(sd, expected) {
		t.Errorf("_sd = %v, want %v", sd, expected)
	}

	// Check _sd_decoy
	decoy, ok := m["_sd_decoy"].(int)
	if !ok || decoy != 2 {
		t.Errorf("_sd_decoy = %v, want 2", m["_sd_decoy"])
	}

	// Check nested
	nested, ok := m["address"].(map[string]any)
	if !ok {
		t.Fatal("address should be a map")
	}
	nestedSD, ok := nested["_sd"].([]string)
	if !ok || len(nestedSD) != 1 || nestedSD[0] != "street" {
		t.Errorf("address._sd = %v, want [street]", nested["_sd"])
	}
}

func TestPresentationFrameToMap(t *testing.T) {
	frame := NewPresentationFrame("name", "email")
	frame.WithNested("address", NewPresentationFrame("city"))

	m := frame.ToMap()

	if m["name"] != true || m["email"] != true {
		t.Error("Top-level claims should be true")
	}

	nested, ok := m["address"].(map[string]any)
	if !ok {
		t.Fatal("address should be a map")
	}
	if nested["city"] != true {
		t.Error("address.city should be true")
	}
}

func TestExtractSDAlg(t *testing.T) {
	t.Run("with _sd_alg", func(t *testing.T) {
		payload := map[string]any{
			"_sd_alg": "sha-384",
			"iss":     "issuer",
		}
		alg := ExtractSDAlg(payload)
		if alg != "sha-384" {
			t.Errorf("ExtractSDAlg = %q, want sha-384", alg)
		}
	})

	t.Run("without _sd_alg", func(t *testing.T) {
		payload := map[string]any{
			"iss": "issuer",
		}
		alg := ExtractSDAlg(payload)
		if alg != DefaultHashAlgorithm {
			t.Errorf("ExtractSDAlg = %q, want %q", alg, DefaultHashAlgorithm)
		}
	})
}

func TestCleanPayload(t *testing.T) {
	payload := map[string]any{
		"iss":     "issuer",
		"sub":     "subject",
		"_sd":     []string{"abc", "def"},
		"_sd_alg": "sha-256",
	}

	cleaned := CleanPayload(payload)

	if _, ok := cleaned["_sd"]; ok {
		t.Error("Cleaned payload should not have _sd")
	}
	if _, ok := cleaned["_sd_alg"]; ok {
		t.Error("Cleaned payload should not have _sd_alg")
	}
	if cleaned["iss"] != "issuer" {
		t.Error("Cleaned payload should preserve iss")
	}
	if cleaned["sub"] != "subject" {
		t.Error("Cleaned payload should preserve sub")
	}
}

func TestNilFrameMethods(t *testing.T) {
	var df *DisclosureFrame
	var pf *PresentationFrame

	if df.HasSD("anything") {
		t.Error("nil DisclosureFrame.HasSD should return false")
	}
	if df.GetNested("anything") != nil {
		t.Error("nil DisclosureFrame.GetNested should return nil")
	}
	if pf.ShouldInclude("anything") {
		t.Error("nil PresentationFrame.ShouldInclude should return false")
	}
	if pf.GetNested("anything") != nil {
		t.Error("nil PresentationFrame.GetNested should return nil")
	}
	if df.ToMap() != nil {
		t.Error("nil DisclosureFrame.ToMap should return nil")
	}
	if pf.ToMap() != nil {
		t.Error("nil PresentationFrame.ToMap should return nil")
	}
}
