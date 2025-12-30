package holder

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
)

// PresentWithFrame creates a presentation using a presentation frame.
// frame specifies which claims to include in the presentation.
// If frame is nil, all disclosures are included.
func (h *Holder) PresentWithFrame(
	frame *sdjwt.PresentationFrame,
	holderSigner signer.Signer,
	opts KeyBindingOptions,
) (*sdjwt.SDJWTWithKB, error) {
	// Get the disclosures to include
	selectedSDJWT, err := h.SelectWithFrame(frame)
	if err != nil {
		return nil, fmt.Errorf("failed to select disclosures: %w", err)
	}

	// Create the key binding JWT
	kbJWT, err := CreateKeyBindingJWT(selectedSDJWT, holderSigner, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create key binding JWT: %w", err)
	}

	return &sdjwt.SDJWTWithKB{
		SDJWT:         *selectedSDJWT,
		KeyBindingJWT: kbJWT,
	}, nil
}

// PresentWithFrameNoKB creates a presentation without key binding using a presentation frame.
func (h *Holder) PresentWithFrameNoKB(frame *sdjwt.PresentationFrame) (*sdjwt.SDJWT, error) {
	return h.SelectWithFrame(frame)
}

// SelectWithFrame selects disclosures based on a presentation frame.
// Returns a new SD-JWT with only the selected disclosures.
func (h *Holder) SelectWithFrame(frame *sdjwt.PresentationFrame) (*sdjwt.SDJWT, error) {
	if frame == nil {
		// Include all disclosures
		return h.SDJWT, nil
	}

	// Parse the JWT payload to understand the structure
	payload, err := h.getJWTPayload()
	if err != nil {
		return nil, err
	}

	// Build a map of disclosure key paths to digests
	keyToDigest := h.buildDisclosureKeyMap(payload)

	// Get the keys to present from the frame
	keysToPresent := flattenPresentationFrame(frame, "")

	// Select the disclosures for the requested keys
	selectedDigests := make(map[string]bool)
	for _, key := range keysToPresent {
		if digest, ok := keyToDigest[key]; ok {
			selectedDigests[digest] = true
			// Also include parent disclosures
			h.includeParentDigests(key, keyToDigest, selectedDigests)
		}
	}

	return h.SDJWT.SelectDisclosures(selectedDigests), nil
}

// buildDisclosureKeyMap builds a map from disclosure key paths to digests.
func (h *Holder) buildDisclosureKeyMap(payload map[string]any) map[string]string {
	result := make(map[string]string)

	// First, map all disclosures by digest to their claim names/values
	disclosureByDigest := make(map[string]*sdjwt.Disclosure)
	for i := range h.SDJWT.Disclosures {
		d := &h.SDJWT.Disclosures[i]
		disclosureByDigest[d.Digest] = d
	}

	// Walk the payload to build the key map
	h.walkPayloadForKeys(payload, "", disclosureByDigest, result)

	return result
}

// walkPayloadForKeys walks the payload and builds the key-to-digest map.
func (h *Holder) walkPayloadForKeys(value any, prefix string, disclosureByDigest map[string]*sdjwt.Disclosure, result map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		// Check for _sd array - handle both []any and []string types
		var digests []string
		if sdArr, ok := v["_sd"].([]any); ok {
			for _, item := range sdArr {
				if digest, ok := item.(string); ok {
					digests = append(digests, digest)
				}
			}
		} else if sdArr, ok := v["_sd"].([]string); ok {
			digests = sdArr
		}

		for _, digest := range digests {
			if d, found := disclosureByDigest[digest]; found && !d.IsArrayElement() {
				key := d.ClaimName
				if prefix != "" {
					key = prefix + "." + key
				}
				result[key] = digest
				// Recursively process the disclosed value
				h.walkPayloadForKeys(d.ClaimValue, key, disclosureByDigest, result)
			}
		}

		// Walk nested objects
		for key, val := range v {
			if key == "_sd" || key == "_sd_alg" {
				continue
			}
			newKey := key
			if prefix != "" {
				newKey = prefix + "." + key
			}
			h.walkPayloadForKeys(val, newKey, disclosureByDigest, result)
		}

	case []any:
		for idx, item := range v {
			idxStr := strconv.Itoa(idx)
			newKey := idxStr
			if prefix != "" {
				newKey = prefix + "." + idxStr
			}

			// Check if this is a digest placeholder {"...": "<digest>"}
			if m, ok := item.(map[string]any); ok {
				if digest, found := m["..."]; found {
					if digestStr, ok := digest.(string); ok {
						if d, found := disclosureByDigest[digestStr]; found {
							result[newKey] = digestStr
							// Recursively process the disclosed value
							h.walkPayloadForKeys(d.ClaimValue, newKey, disclosureByDigest, result)
						}
						continue
					}
				}
			}

			// Regular array element
			h.walkPayloadForKeys(item, newKey, disclosureByDigest, result)
		}
	}
}

// includeParentDigests includes any parent disclosures needed for a key.
func (h *Holder) includeParentDigests(key string, keyToDigest map[string]string, selected map[string]bool) {
	parts := strings.Split(key, ".")
	for i := len(parts) - 1; i > 0; i-- {
		parentKey := strings.Join(parts[:i], ".")
		if digest, ok := keyToDigest[parentKey]; ok {
			selected[digest] = true
		}
	}
}

// flattenPresentationFrame converts a presentation frame to a list of key paths.
func flattenPresentationFrame(frame *sdjwt.PresentationFrame, prefix string) []string {
	if frame == nil {
		return nil
	}

	var keys []string

	// Add included keys at this level
	for key, include := range frame.Include {
		if include {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			keys = append(keys, fullKey)
		}
	}

	// Recursively add nested keys
	for key, nestedFrame := range frame.Nested {
		nestedPrefix := key
		if prefix != "" {
			nestedPrefix = prefix + "." + key
		}
		keys = append(keys, flattenPresentationFrame(nestedFrame, nestedPrefix)...)
	}

	return keys
}

// GetPresentableKeys returns all keys that can be presented (i.e., have disclosures).
// This is useful for inspecting what claims can be selectively disclosed.
func (h *Holder) GetPresentableKeys() ([]string, error) {
	payload, err := h.getJWTPayload()
	if err != nil {
		return nil, err
	}

	keyToDigest := h.buildDisclosureKeyMap(payload)

	keys := make([]string, 0, len(keyToDigest))
	for key := range keyToDigest {
		keys = append(keys, key)
	}

	return keys, nil
}

// GetAllKeys returns all claim keys in the SD-JWT (both disclosed and non-disclosed).
func (h *Holder) GetAllKeys() ([]string, error) {
	processed, err := h.GetProcessedPayload()
	if err != nil {
		return nil, err
	}

	return listKeys(processed.Claims, ""), nil
}

// listKeys recursively lists all keys in a map.
func listKeys(obj map[string]any, prefix string) []string {
	var keys []string

	for key, value := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		keys = append(keys, fullKey)

		switch v := value.(type) {
		case map[string]any:
			keys = append(keys, listKeys(v, fullKey)...)
		case []any:
			for idx, item := range v {
				idxKey := fullKey + "." + strconv.Itoa(idx)
				keys = append(keys, idxKey)
				if m, ok := item.(map[string]any); ok {
					keys = append(keys, listKeys(m, idxKey)...)
				}
			}
		}
	}

	return keys
}
