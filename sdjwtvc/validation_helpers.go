package sdjwtvc

import (
	"fmt"
	"regexp"

	"github.com/georgepadayatti/sdjwt/sdjwt"
)

var integrityMetadataPattern = regexp.MustCompile(`^(sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+$`)

func validateIntegrityMetadata(value string) error {
	parts := splitIntegrityMetadata(value)
	if len(parts) == 0 {
		return fmt.Errorf("integrity metadata must not be empty")
	}
	for _, part := range parts {
		if !integrityMetadataPattern.MatchString(part) {
			return fmt.Errorf("invalid integrity metadata entry: %s", part)
		}
	}
	return nil
}

func splitIntegrityMetadata(value string) []string {
	var parts []string
	for _, part := range regexp.MustCompile(`\s+`).Split(value, -1) {
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	return parts
}

func validateStatusClaim(statusRaw any) error {
	statusMap, ok := statusRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("status must be an object")
	}
	statusListRaw, ok := statusMap["status_list"]
	if !ok {
		return fmt.Errorf("status.status_list is required")
	}
	statusList, ok := statusListRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("status.status_list must be an object")
	}
	idx, err := toInt64(statusList["idx"])
	if err != nil {
		return fmt.Errorf("status.status_list.idx must be a number: %w", err)
	}
	if idx < 0 {
		return fmt.Errorf("status.status_list.idx must be non-negative")
	}
	uri, ok := statusList["uri"].(string)
	if !ok || uri == "" {
		return fmt.Errorf("status.status_list.uri must be a non-empty string")
	}
	return nil
}

func validateCNFClaim(cnfRaw any) error {
	cnfMap, ok := cnfRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("cnf must be an object")
	}

	if jwkRaw, ok := cnfMap["jwk"]; ok {
		if _, ok := jwkRaw.(map[string]any); !ok {
			return fmt.Errorf("cnf.jwk must be an object")
		}
		return nil
	}

	if x5cRaw, ok := cnfMap["x5c"]; ok {
		if _, ok := x5cRaw.([]any); !ok {
			return fmt.Errorf("cnf.x5c must be an array")
		}
		return nil
	}

	if x5uRaw, ok := cnfMap["x5u"]; ok {
		x5u, ok := x5uRaw.(string)
		if !ok || x5u == "" {
			return fmt.Errorf("cnf.x5u must be a non-empty string")
		}
		if x5t, ok := cnfMap["x5t#S256"]; !ok || x5t == "" {
			return fmt.Errorf("cnf.x5t#S256 is required when cnf.x5u is present")
		}
		return nil
	}

	return fmt.Errorf("cnf must contain jwk, x5c, or x5u/x5t#S256")
}

func validateSDFrameTopLevel(frame *sdjwt.DisclosureFrame) error {
	if frame == nil {
		return nil
	}
	for _, name := range frame.SD {
		if MustNotBeSelectivelyDisclosed(name) {
			return fmt.Errorf("claim %q must not be selectively disclosed", name)
		}
	}
	for key := range frame.Nested {
		if MustNotBeSelectivelyDisclosed(key) {
			return fmt.Errorf("claim %q must not be selectively disclosed", key)
		}
	}
	return nil
}

func frameHasSDClaims(frame *sdjwt.DisclosureFrame) bool {
	if frame == nil {
		return false
	}
	if len(frame.SD) > 0 {
		return true
	}
	for _, nested := range frame.Nested {
		if frameHasSDClaims(nested) {
			return true
		}
	}
	return false
}

func frameHasDecoys(frame *sdjwt.DisclosureFrame) bool {
	if frame == nil {
		return false
	}
	if frame.SDDecoy > 0 {
		return true
	}
	for _, nested := range frame.Nested {
		if frameHasDecoys(nested) {
			return true
		}
	}
	return false
}
