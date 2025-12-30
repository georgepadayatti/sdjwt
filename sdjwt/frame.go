package sdjwt

// DisclosureFrame specifies which claims should be selectively disclosable.
//
// Example:
//
//	claims := map[string]any{
//	    "firstname": "John",
//	    "lastname": "Doe",
//	    "address": map[string]any{
//	        "street": "123 Main St",
//	        "city": "Anytown",
//	    },
//	}
//
//	frame := &DisclosureFrame{
//	    SD: []string{"firstname", "lastname"},  // These top-level claims will be SD
//	    Nested: map[string]*DisclosureFrame{
//	        "address": {
//	            SD: []string{"street"},  // street within address will be SD
//	        },
//	    },
//	}
type DisclosureFrame struct {
	// SD is a list of claim names to make selectively disclosable at this level.
	// For arrays, this should contain indices as strings (e.g., "0", "1").
	SD []string `json:"_sd,omitempty"`

	// SDDecoy is the number of decoy digests to add at this level.
	SDDecoy int `json:"_sd_decoy,omitempty"`

	// Nested contains disclosure frames for nested objects.
	// The key is the claim name, and the value is the disclosure frame for that claim.
	Nested map[string]*DisclosureFrame `json:"-"`
}

// PresentationFrame specifies which claims to include in a presentation.
//
// Example:
//
//	frame := &PresentationFrame{
//	    Include: map[string]bool{
//	        "firstname": true,
//	        "address": true,
//	    },
//	    Nested: map[string]*PresentationFrame{
//	        "address": {
//	            Include: map[string]bool{"city": true},
//	        },
//	    },
//	}
type PresentationFrame struct {
	// Include is a map of claim names to include in the presentation.
	// For arrays, use string indices as keys (e.g., "0", "1").
	Include map[string]bool `json:"-"`

	// Nested contains presentation frames for nested objects.
	Nested map[string]*PresentationFrame `json:"-"`
}

// Constants for disclosure frame keys
const (
	SDDigestKey = "_sd"
	SDDecoyKey  = "_sd_decoy"
	SDListKey   = "..."
)

// HasSD checks if a claim name is in the SD list.
func (f *DisclosureFrame) HasSD(claimName string) bool {
	if f == nil {
		return false
	}
	for _, name := range f.SD {
		if name == claimName {
			return true
		}
	}
	return false
}

// GetNested returns the nested disclosure frame for a claim, if any.
func (f *DisclosureFrame) GetNested(claimName string) *DisclosureFrame {
	if f == nil || f.Nested == nil {
		return nil
	}
	return f.Nested[claimName]
}

// ShouldInclude checks if a claim should be included in the presentation.
func (f *PresentationFrame) ShouldInclude(claimName string) bool {
	if f == nil || f.Include == nil {
		return false
	}
	return f.Include[claimName]
}

// GetNested returns the nested presentation frame for a claim, if any.
func (f *PresentationFrame) GetNested(claimName string) *PresentationFrame {
	if f == nil || f.Nested == nil {
		return nil
	}
	return f.Nested[claimName]
}

// ExtractSDAlg extracts _sd_alg from a payload, defaulting to sha-256 if not present.
func ExtractSDAlg(payload map[string]any) string {
	if alg, ok := payload["_sd_alg"].(string); ok {
		return alg
	}
	// Default to sha-256 for backward compatibility
	return DefaultHashAlgorithm
}

// CleanPayload removes _sd and _sd_alg from a payload for processing.
// Returns a copy of the payload without these special claims.
func CleanPayload(payload map[string]any) map[string]any {
	result := make(map[string]any)
	for key, value := range payload {
		if key == "_sd" || key == "_sd_alg" {
			continue
		}
		result[key] = value
	}
	return result
}

// NewDisclosureFrame creates a new DisclosureFrame with the given SD claims.
func NewDisclosureFrame(sd ...string) *DisclosureFrame {
	return &DisclosureFrame{
		SD:     sd,
		Nested: make(map[string]*DisclosureFrame),
	}
}

// WithDecoys adds decoy digests to the frame.
func (f *DisclosureFrame) WithDecoys(count int) *DisclosureFrame {
	f.SDDecoy = count
	return f
}

// WithNested adds a nested frame for a claim.
func (f *DisclosureFrame) WithNested(key string, nested *DisclosureFrame) *DisclosureFrame {
	if f.Nested == nil {
		f.Nested = make(map[string]*DisclosureFrame)
	}
	f.Nested[key] = nested
	return f
}

// NewPresentationFrame creates a new PresentationFrame with the given claims to include.
func NewPresentationFrame(claims ...string) *PresentationFrame {
	include := make(map[string]bool)
	for _, c := range claims {
		include[c] = true
	}
	return &PresentationFrame{
		Include: include,
		Nested:  make(map[string]*PresentationFrame),
	}
}

// AddClaim adds a claim to include in the presentation.
func (f *PresentationFrame) AddClaim(name string) *PresentationFrame {
	if f.Include == nil {
		f.Include = make(map[string]bool)
	}
	f.Include[name] = true
	return f
}

// WithNested adds a nested frame for a claim.
func (f *PresentationFrame) WithNested(key string, nested *PresentationFrame) *PresentationFrame {
	if f.Nested == nil {
		f.Nested = make(map[string]*PresentationFrame)
	}
	f.Nested[key] = nested
	return f
}

// AllDisclosures returns a PresentationFrame that includes all available disclosures.
// This is used when you want to present all disclosures without filtering.
func AllDisclosures() *PresentationFrame {
	return nil // nil means include all
}

// MergeDisclosureFrames merges multiple disclosure frames into one.
// Later frames override earlier ones for the same keys.
func MergeDisclosureFrames(frames ...*DisclosureFrame) *DisclosureFrame {
	result := &DisclosureFrame{
		SD:     []string{},
		Nested: make(map[string]*DisclosureFrame),
	}

	sdSet := make(map[string]bool)

	for _, f := range frames {
		if f == nil {
			continue
		}

		// Merge SD claims
		for _, sd := range f.SD {
			if !sdSet[sd] {
				sdSet[sd] = true
				result.SD = append(result.SD, sd)
			}
		}

		// Take max decoy count
		if f.SDDecoy > result.SDDecoy {
			result.SDDecoy = f.SDDecoy
		}

		// Merge nested frames
		for key, nested := range f.Nested {
			if existing, ok := result.Nested[key]; ok {
				result.Nested[key] = MergeDisclosureFrames(existing, nested)
			} else {
				result.Nested[key] = nested
			}
		}
	}

	return result
}

// MergePresentationFrames merges multiple presentation frames into one.
// Later frames override earlier ones for the same keys.
func MergePresentationFrames(frames ...*PresentationFrame) *PresentationFrame {
	result := &PresentationFrame{
		Include: make(map[string]bool),
		Nested:  make(map[string]*PresentationFrame),
	}

	for _, f := range frames {
		if f == nil {
			continue
		}

		// Merge includes
		for key, include := range f.Include {
			result.Include[key] = include
		}

		// Merge nested frames
		for key, nested := range f.Nested {
			if existing, ok := result.Nested[key]; ok {
				result.Nested[key] = MergePresentationFrames(existing, nested)
			} else {
				result.Nested[key] = nested
			}
		}
	}

	return result
}

// DisclosureFrameFromMap creates a DisclosureFrame from a map representation.
// This is useful for parsing frames from JSON or other dynamic sources.
// Map format:
//
//	{
//	  "_sd": ["claim1", "claim2"],
//	  "_sd_decoy": 2,
//	  "nested_claim": { "_sd": ["nested_field"] }
//	}
func DisclosureFrameFromMap(m map[string]any) *DisclosureFrame {
	if m == nil {
		return nil
	}

	frame := &DisclosureFrame{
		Nested: make(map[string]*DisclosureFrame),
	}

	// Parse _sd array
	if sd, ok := m[SDDigestKey]; ok {
		if sdArr, ok := sd.([]any); ok {
			for _, item := range sdArr {
				if s, ok := item.(string); ok {
					frame.SD = append(frame.SD, s)
				}
			}
		} else if sdStrArr, ok := sd.([]string); ok {
			frame.SD = sdStrArr
		}
	}

	// Parse _sd_decoy
	if decoy, ok := m[SDDecoyKey]; ok {
		switch d := decoy.(type) {
		case int:
			frame.SDDecoy = d
		case float64:
			frame.SDDecoy = int(d)
		}
	}

	// Parse nested frames
	for key, value := range m {
		if key == SDDigestKey || key == SDDecoyKey {
			continue
		}
		if nestedMap, ok := value.(map[string]any); ok {
			frame.Nested[key] = DisclosureFrameFromMap(nestedMap)
		}
	}

	return frame
}

// PresentationFrameFromMap creates a PresentationFrame from a map representation.
// Map format:
//
//	{
//	  "claim1": true,
//	  "claim2": true,
//	  "nested_claim": { "nested_field": true }
//	}
func PresentationFrameFromMap(m map[string]any) *PresentationFrame {
	if m == nil {
		return nil
	}

	frame := &PresentationFrame{
		Include: make(map[string]bool),
		Nested:  make(map[string]*PresentationFrame),
	}

	for key, value := range m {
		switch v := value.(type) {
		case bool:
			frame.Include[key] = v
		case map[string]any:
			frame.Nested[key] = PresentationFrameFromMap(v)
		}
	}

	return frame
}

// ToMap converts a DisclosureFrame to a map representation.
func (f *DisclosureFrame) ToMap() map[string]any {
	if f == nil {
		return nil
	}

	result := make(map[string]any)

	if len(f.SD) > 0 {
		result[SDDigestKey] = f.SD
	}

	if f.SDDecoy > 0 {
		result[SDDecoyKey] = f.SDDecoy
	}

	for key, nested := range f.Nested {
		result[key] = nested.ToMap()
	}

	return result
}

// ToMap converts a PresentationFrame to a map representation.
func (f *PresentationFrame) ToMap() map[string]any {
	if f == nil {
		return nil
	}

	result := make(map[string]any)

	for key, include := range f.Include {
		result[key] = include
	}

	for key, nested := range f.Nested {
		result[key] = nested.ToMap()
	}

	return result
}
