package sdjwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ProcessSDJWTPayload validates and processes an SD-JWT payload with the provided disclosures.
// It enforces the verification and processing requirements in RFC 9901 Section 7.1.
func ProcessSDJWTPayload(payload map[string]any, disclosures []Disclosure, hashAlgorithm string) (map[string]any, []string, error) {
	resolvedAlg, err := resolveHashAlgorithm(payload, hashAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	if !IsSupportedHashAlgorithm(resolvedAlg) {
		return nil, nil, fmt.Errorf("unsupported hash algorithm: %s", resolvedAlg)
	}

	disclosureMap := make(map[string]*Disclosure)
	for i := range disclosures {
		d := &disclosures[i]
		if _, exists := disclosureMap[d.Digest]; exists {
			return nil, nil, fmt.Errorf("duplicate disclosure digest: %s", d.Digest)
		}
		disclosureMap[d.Digest] = d
	}

	usedDigests := make(map[string]bool)
	usedDisclosures := make(map[string]bool)

	processed, disclosedClaims, err := processValue(payload, disclosureMap, usedDigests, usedDisclosures, "", true)
	if err != nil {
		return nil, nil, err
	}

	processedObj, ok := processed.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("processed payload is not an object")
	}

	if len(usedDisclosures) != len(disclosureMap) {
		var unused []string
		for digest := range disclosureMap {
			if !usedDisclosures[digest] {
				unused = append(unused, digest)
			}
		}
		return nil, nil, fmt.Errorf("unused disclosures present: %v", unused)
	}

	return processedObj, disclosedClaims, nil
}

func processValue(value any, disclosureMap map[string]*Disclosure, usedDigests map[string]bool, usedDisclosures map[string]bool, prefix string, allowSDAlg bool) (any, []string, error) {
	switch v := value.(type) {
	case map[string]any:
		return processObject(v, disclosureMap, usedDigests, usedDisclosures, prefix, allowSDAlg)
	case []any:
		return processArray(v, disclosureMap, usedDigests, usedDisclosures, prefix)
	default:
		return value, nil, nil
	}
}

func processObject(obj map[string]any, disclosureMap map[string]*Disclosure, usedDigests map[string]bool, usedDisclosures map[string]bool, prefix string, allowSDAlg bool) (map[string]any, []string, error) {
	result := make(map[string]any)
	var disclosedClaims []string

	existingKeys := make(map[string]bool)
	for key, value := range obj {
		if key == SDListKey {
			return nil, nil, fmt.Errorf("invalid claim name: %s", SDListKey)
		}
		if key == "_sd" || key == "_sd_alg" {
			continue
		}

		existingKeys[key] = true

		processed, nestedClaims, err := processValue(value, disclosureMap, usedDigests, usedDisclosures, joinPath(prefix, key), false)
		if err != nil {
			return nil, nil, err
		}
		result[key] = processed
		disclosedClaims = append(disclosedClaims, nestedClaims...)
	}

	if sdAlg, ok := obj["_sd_alg"]; ok {
		if !allowSDAlg {
			return nil, nil, fmt.Errorf("_sd_alg must only appear at the top level")
		}
		if _, ok := sdAlg.(string); !ok {
			return nil, nil, fmt.Errorf("_sd_alg must be a string")
		}
	}

	if sdVal, ok := obj["_sd"]; ok {
		digests, err := parseDigestArray(sdVal)
		if err != nil {
			return nil, nil, err
		}

		for _, digest := range digests {
			if usedDigests[digest] {
				return nil, nil, fmt.Errorf("duplicate digest encountered: %s", digest)
			}
			usedDigests[digest] = true

			d, found := disclosureMap[digest]
			if !found {
				continue
			}
			if d.IsArrayElement() {
				return nil, nil, fmt.Errorf("object disclosure must have 3 elements")
			}
			if d.ClaimName == "_sd" || d.ClaimName == SDListKey {
				return nil, nil, fmt.Errorf("invalid disclosure claim name: %s", d.ClaimName)
			}
			if existingKeys[d.ClaimName] {
				return nil, nil, fmt.Errorf("duplicate claim name at level: %s", d.ClaimName)
			}

			claimPath := joinPath(prefix, d.ClaimName)
			processedValue, nestedClaims, err := processValue(d.ClaimValue, disclosureMap, usedDigests, usedDisclosures, claimPath, false)
			if err != nil {
				return nil, nil, err
			}
			result[d.ClaimName] = processedValue
			existingKeys[d.ClaimName] = true
			usedDisclosures[d.Digest] = true
			disclosedClaims = append(disclosedClaims, claimPath)
			disclosedClaims = append(disclosedClaims, nestedClaims...)
		}
	}

	return result, disclosedClaims, nil
}

func processArray(arr []any, disclosureMap map[string]*Disclosure, usedDigests map[string]bool, usedDisclosures map[string]bool, prefix string) ([]any, []string, error) {
	var result []any
	var disclosedClaims []string

	for i, item := range arr {
		if m, ok := item.(map[string]any); ok {
			if digestRaw, found := m[SDListKey]; found {
				if len(m) != 1 {
					return nil, nil, fmt.Errorf("array element digest object must contain only %s", SDListKey)
				}
				digestStr, ok := digestRaw.(string)
				if !ok {
					return nil, nil, fmt.Errorf("array element digest must be a string")
				}
				if usedDigests[digestStr] {
					return nil, nil, fmt.Errorf("duplicate digest encountered: %s", digestStr)
				}
				usedDigests[digestStr] = true

				d, found := disclosureMap[digestStr]
				if !found {
					continue
				}
				if !d.IsArrayElement() {
					return nil, nil, fmt.Errorf("array disclosure must have 2 elements")
				}

				elementPath := fmt.Sprintf("%s[%d]", prefix, i)
				processedValue, nestedClaims, err := processValue(d.ClaimValue, disclosureMap, usedDigests, usedDisclosures, elementPath, false)
				if err != nil {
					return nil, nil, err
				}
				result = append(result, processedValue)
				usedDisclosures[d.Digest] = true
				disclosedClaims = append(disclosedClaims, elementPath)
				disclosedClaims = append(disclosedClaims, nestedClaims...)
				continue
			}

			processed, nestedClaims, err := processObject(m, disclosureMap, usedDigests, usedDisclosures, fmt.Sprintf("%s[%d]", prefix, i), false)
			if err != nil {
				return nil, nil, err
			}
			result = append(result, processed)
			disclosedClaims = append(disclosedClaims, nestedClaims...)
			continue
		}

		if nestedArr, ok := item.([]any); ok {
			processed, nestedClaims, err := processArray(nestedArr, disclosureMap, usedDigests, usedDisclosures, fmt.Sprintf("%s[%d]", prefix, i))
			if err != nil {
				return nil, nil, err
			}
			result = append(result, processed)
			disclosedClaims = append(disclosedClaims, nestedClaims...)
			continue
		}

		result = append(result, item)
	}

	return result, disclosedClaims, nil
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

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func resolveHashAlgorithm(payload map[string]any, provided string) (string, error) {
	if sdAlgRaw, ok := payload["_sd_alg"]; ok {
		sdAlg, ok := sdAlgRaw.(string)
		if !ok {
			return "", fmt.Errorf("_sd_alg must be a string")
		}
		if provided != "" && provided != sdAlg {
			return "", fmt.Errorf("hash algorithm mismatch: payload=%s provided=%s", sdAlg, provided)
		}
		return sdAlg, nil
	}

	if provided != "" && provided != DefaultHashAlgorithm {
		return "", fmt.Errorf("hash algorithm mismatch: payload=%s provided=%s", DefaultHashAlgorithm, provided)
	}
	return DefaultHashAlgorithm, nil
}

func resolveHashAlgorithmFromJWT(jwtString string, provided string) (string, error) {
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	return resolveHashAlgorithmFromPayload(parts[1], provided)
}

func resolveHashAlgorithmFromPayload(payloadBase64 string, provided string) (string, error) {
	payloadBytes, err := Base64URLDecode(payloadBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	return resolveHashAlgorithm(payload, provided)
}

func buildJSONHeader(disclosures []Disclosure, kbJWT string) *SDJWTJSONHeader {
	var header SDJWTJSONHeader
	if len(disclosures) > 0 {
		header.Disclosures = make([]string, len(disclosures))
		for i, d := range disclosures {
			header.Disclosures[i] = d.Encoded
		}
	}
	if kbJWT != "" {
		header.KBJwt = kbJWT
	}
	if len(header.Disclosures) == 0 && header.KBJwt == "" {
		return nil
	}
	return &header
}

func disclosuresFromJSONHeader(header *SDJWTJSONHeader) ([]string, string, error) {
	if header == nil {
		return nil, "", nil
	}
	return header.Disclosures, header.KBJwt, nil
}
