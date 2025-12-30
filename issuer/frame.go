package issuer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/georgepadayatti/sdjwt/sdjwt"
	"github.com/georgepadayatti/sdjwt/signer"
	"github.com/golang-jwt/jwt/v5"
)

// IssueWithFrame creates an SD-JWT using the disclosure frame pattern.
// claims is a map of claim name to claim value.
// frame specifies which claims should be selectively disclosable.
// If frame is nil, no claims will be selectively disclosable.
func (i *Issuer) IssueWithFrame(claims map[string]any, frame *sdjwt.DisclosureFrame, opts *IssueOptions) (*sdjwt.SDJWT, error) {
	if i.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if opts == nil {
		opts = &IssueOptions{}
	}

	hashAlg := opts.HashAlgorithm
	if hashAlg == "" {
		hashAlg = sdjwt.DefaultHashAlgorithm
	}

	if !sdjwt.IsSupportedHashAlgorithm(hashAlg) {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlg)
	}

	if err := validateNoReservedKeys(claims); err != nil {
		return nil, err
	}

	// Pack the claims with the disclosure frame
	packedClaims, disclosures, err := packClaims(claims, frame, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to pack claims: %w", err)
	}

	// Add _sd_alg only when there are disclosures
	if len(disclosures) > 0 {
		packedClaims["_sd_alg"] = hashAlg
	}

	// Add holder's public key for key binding
	if len(opts.HolderPublicKey) > 0 {
		var jwk map[string]any
		if err := json.Unmarshal(opts.HolderPublicKey, &jwk); err != nil {
			return nil, fmt.Errorf("invalid holder public key: %w", err)
		}
		packedClaims["cnf"] = map[string]any{"jwk": jwk}
	}

	if err := ensureUniqueSalts(disclosures); err != nil {
		return nil, err
	}

	if err := ensureUniqueDigests(packedClaims); err != nil {
		return nil, err
	}

	// Create the JWT using the Signer's SigningMethod adapter
	signingMethod := signer.NewSigningMethod(i.Signer)
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims(packedClaims))

	// Set type header if provided
	if opts.Type != "" {
		token.Header["typ"] = opts.Type
	}

	// Add extra headers (e.g., x5c, x5u, x5t#S256 for ETSI EAA)
	for k, v := range opts.ExtraHeaders {
		token.Header[k] = v
	}

	// Sign the token (key is nil since Signer manages its own key)
	signedJWT, err := token.SignedString(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	return &sdjwt.SDJWT{
		IssuerSignedJWT: signedJWT,
		Disclosures:     disclosures,
		HashAlgorithm:   hashAlg,
	}, nil
}

func validateNoReservedKeys(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, val := range v {
			if key == "_sd" || key == "_sd_alg" || key == sdjwt.SDListKey {
				return fmt.Errorf("reserved claim name %q is not allowed in input", key)
			}
			if err := validateNoReservedKeys(val); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := validateNoReservedKeys(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureUniqueSalts(disclosures []sdjwt.Disclosure) error {
	seen := make(map[string]bool)
	for _, d := range disclosures {
		if d.Salt == "" {
			continue
		}
		if seen[d.Salt] {
			return fmt.Errorf("duplicate disclosure salt detected")
		}
		seen[d.Salt] = true
	}
	return nil
}

func ensureUniqueDigests(value any) error {
	seen := make(map[string]bool)
	return collectDigests(value, seen)
}

func collectDigests(value any, seen map[string]bool) error {
	switch v := value.(type) {
	case map[string]any:
		if sdVal, ok := v["_sd"]; ok {
			digests, err := parseDigestArray(sdVal)
			if err != nil {
				return err
			}
			for _, digest := range digests {
				if seen[digest] {
					return fmt.Errorf("duplicate digest detected: %s", digest)
				}
				seen[digest] = true
			}
		}
		for _, val := range v {
			if err := collectDigests(val, seen); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if digestRaw, found := m[sdjwt.SDListKey]; found {
					digestStr, ok := digestRaw.(string)
					if !ok {
						return fmt.Errorf("array element digest must be a string")
					}
					if seen[digestStr] {
						return fmt.Errorf("duplicate digest detected: %s", digestStr)
					}
					seen[digestStr] = true
				}
			}
			if err := collectDigests(item, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseDigestArray(value any) ([]string, error) {
	switch v := value.(type) {
	case []string:
		return v, nil
	case []any:
		digests := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("_sd must be an array of strings")
			}
			digests = append(digests, str)
		}
		return digests, nil
	default:
		return nil, fmt.Errorf("_sd must be an array of strings")
	}
}

// IssueOptions contains options for issuing an SD-JWT.
type IssueOptions struct {
	// HashAlgorithm is the hash algorithm to use (default: sha-256)
	HashAlgorithm string

	// HolderPublicKey is the holder's public key in JWK format for key binding
	HolderPublicKey json.RawMessage

	// Type is the JWT type header (e.g., "sd+jwt" or "vc+sd-jwt")
	Type string

	// ExtraHeaders contains additional JWT header parameters (e.g., x5c, x5u, x5t#S256)
	// These are merged into the JWT header.
	ExtraHeaders map[string]any
}

// packClaims packs claims according to the disclosure frame.
// Returns the packed claims map, disclosures, and any error.
func packClaims(claims map[string]any, frame *sdjwt.DisclosureFrame, hashAlg string) (map[string]any, []sdjwt.Disclosure, error) {
	if frame == nil {
		// No disclosure frame, return claims as-is
		result := make(map[string]any)
		for k, v := range claims {
			result[k] = v
		}
		return result, nil, nil
	}

	return packObject(claims, frame, hashAlg)
}

// packObject packs an object (map) according to the disclosure frame.
func packObject(obj map[string]any, frame *sdjwt.DisclosureFrame, hashAlg string) (map[string]any, []sdjwt.Disclosure, error) {
	result := make(map[string]any)
	var disclosures []sdjwt.Disclosure
	var sdDigests []string

	for key, value := range obj {
		// Validate claim name
		if err := sdjwt.ValidateDisclosureClaimName(key); err != nil {
			return nil, nil, err
		}

		// Check if there's a nested frame for this key
		nestedFrame := frame.GetNested(key)

		// Process the value recursively if it's an object or array
		processedValue, nestedDisclosures, err := processValue(value, nestedFrame, hashAlg)
		if err != nil {
			return nil, nil, err
		}
		disclosures = append(disclosures, nestedDisclosures...)

		// Check if this claim should be disclosed
		if frame.HasSD(key) {
			// Create a disclosure for this claim
			d, err := sdjwt.NewDisclosure(key, processedValue, hashAlg)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create disclosure for %s: %w", key, err)
			}
			disclosures = append(disclosures, *d)
			sdDigests = append(sdDigests, d.Digest)
		} else {
			// Add to result directly
			result[key] = processedValue
		}
	}

	// Add decoy digests
	for j := 0; j < frame.SDDecoy; j++ {
		decoy, err := sdjwt.GenerateDecoyDigest(hashAlg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate decoy: %w", err)
		}
		sdDigests = append(sdDigests, decoy)
	}

	// Add _sd array if there are any digests
	if len(sdDigests) > 0 {
		// Sort digests to hide original order
		sort.Strings(sdDigests)
		result["_sd"] = sdDigests
	}

	return result, disclosures, nil
}

// packArray packs an array according to the disclosure frame.
func packArray(arr []any, frame *sdjwt.DisclosureFrame, hashAlg string) ([]any, []sdjwt.Disclosure, error) {
	result := make([]any, 0, len(arr))
	var disclosures []sdjwt.Disclosure

	for idx, item := range arr {
		idxStr := strconv.Itoa(idx)

		// Check if there's a nested frame for this index
		nestedFrame := frame.GetNested(idxStr)

		// Process the value recursively
		processedValue, nestedDisclosures, err := processValue(item, nestedFrame, hashAlg)
		if err != nil {
			return nil, nil, err
		}
		disclosures = append(disclosures, nestedDisclosures...)

		// Check if this index should be disclosed
		if frame.HasSD(idxStr) {
			// Create an array element disclosure
			d, err := sdjwt.NewArrayElementDisclosure(processedValue, hashAlg)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create array disclosure for index %d: %w", idx, err)
			}
			disclosures = append(disclosures, *d)
			// Add digest placeholder
			result = append(result, map[string]string{sdjwt.SDListKey: d.Digest})
		} else {
			result = append(result, processedValue)
		}
	}

	// Add decoy digests for arrays
	for j := 0; j < frame.SDDecoy; j++ {
		decoy, err := sdjwt.GenerateDecoyDigest(hashAlg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate array decoy: %w", err)
		}
		result = append(result, map[string]string{sdjwt.SDListKey: decoy})
	}

	return result, disclosures, nil
}

// processValue processes a value according to its type and frame.
func processValue(value any, frame *sdjwt.DisclosureFrame, hashAlg string) (any, []sdjwt.Disclosure, error) {
	if frame == nil {
		// No frame, return value as-is
		return value, nil, nil
	}

	switch v := value.(type) {
	case map[string]any:
		return packObject(v, frame, hashAlg)
	case []any:
		return packArray(v, frame, hashAlg)
	default:
		// Primitive value, return as-is
		return value, nil, nil
	}
}
