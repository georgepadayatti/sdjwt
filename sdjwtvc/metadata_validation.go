package sdjwtvc

import (
	"fmt"
	"regexp"
)

var svgIDPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateVCTMetadata validates a Type Metadata document per Sections 6-9.
func ValidateVCTMetadata(metadata *VCTMetadata) error {
	if metadata == nil {
		return fmt.Errorf("metadata is required")
	}
	if metadata.VCT == "" {
		return fmt.Errorf("metadata.vct is required")
	}
	if len(metadata.Extends) > 1 {
		return fmt.Errorf("metadata.extends must contain at most one entry")
	}
	if len(metadata.ExtendsIntegrity) > 1 {
		return fmt.Errorf("metadata.extends#integrity must contain at most one entry")
	}
	if len(metadata.ExtendsIntegrity) > 0 && len(metadata.Extends) == 0 {
		return fmt.Errorf("metadata.extends#integrity requires metadata.extends")
	}
	for _, integrity := range metadata.ExtendsIntegrity {
		if err := validateIntegrityMetadata(integrity); err != nil {
			return fmt.Errorf("metadata.extends#integrity is invalid: %w", err)
		}
	}
	if metadata.SchemaIntegrity != "" {
		if err := validateIntegrityMetadata(metadata.SchemaIntegrity); err != nil {
			return fmt.Errorf("metadata.schema#integrity is invalid: %w", err)
		}
	}

	for i, display := range metadata.Display {
		if err := validateTypeDisplayMetadata(display); err != nil {
			return fmt.Errorf("metadata.display[%d]: %w", i, err)
		}
	}

	svgIDs := make(map[string]bool)
	for i, claim := range metadata.Claims {
		if err := ValidateClaimMetadata(claim); err != nil {
			return fmt.Errorf("metadata.claims[%d]: %w", i, err)
		}
		if claim.SVGID != "" {
			if !svgIDPattern.MatchString(claim.SVGID) {
				return fmt.Errorf("metadata.claims[%d]: svg_id must be alphanumeric or underscore and not start with a digit", i)
			}
			if svgIDs[claim.SVGID] {
				return fmt.Errorf("metadata.claims[%d]: svg_id must be unique", i)
			}
			svgIDs[claim.SVGID] = true
		}
	}

	return nil
}

// ValidateVCTMetadataWithParent validates a Type Metadata document against a parent type.
// This enforces Section 9.5.1 constraints for sd and mandatory.
func ValidateVCTMetadataWithParent(metadata *VCTMetadata, parent *VCTMetadata) error {
	if err := ValidateVCTMetadata(metadata); err != nil {
		return err
	}
	if parent == nil {
		return nil
	}

	parentClaims := make(map[string]ClaimMetadata)
	for _, claim := range parent.Claims {
		parentClaims[claim.Path.String()] = claim
	}

	for _, claim := range metadata.Claims {
		parentClaim, ok := parentClaims[claim.Path.String()]
		if !ok {
			continue
		}
		if parentClaim.SD == SDAlways || parentClaim.SD == SDNever {
			if claim.SD != "" && claim.SD != parentClaim.SD {
				return fmt.Errorf("claim %s: sd must not override parent sd=%s", claim.Path.String(), parentClaim.SD)
			}
		}
		if parentClaim.Mandatory && !claim.Mandatory {
			return fmt.Errorf("claim %s: mandatory must not override parent mandatory=true", claim.Path.String())
		}
	}

	return nil
}

// ValidateClaimMetadata validates claim metadata per Section 9.
func ValidateClaimMetadata(claim ClaimMetadata) error {
	if err := ValidateClaimPath(claim.Path); err != nil {
		return err
	}
	if claim.SD != "" && claim.SD != SDAlways && claim.SD != SDAllowed && claim.SD != SDNever {
		return fmt.Errorf("sd must be one of %q, %q, %q", SDAlways, SDAllowed, SDNever)
	}
	for i, display := range claim.Display {
		if err := validateClaimDisplayMetadata(display); err != nil {
			return fmt.Errorf("display[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateClaimPath validates claim paths per Section 9.1.
func ValidateClaimPath(path ClaimPath) error {
	if len(path) == 0 {
		return fmt.Errorf("path must not be empty")
	}
	for _, elem := range path {
		switch v := elem.(type) {
		case string:
			if v == "" {
				return fmt.Errorf("path string elements must not be empty")
			}
		case nil:
		case int:
			if v < 0 {
				return fmt.Errorf("path integer elements must be non-negative")
			}
		case float64:
			if v < 0 || v != float64(int(v)) {
				return fmt.Errorf("path float elements must be non-negative integers")
			}
		default:
			return fmt.Errorf("path elements must be string, null, or non-negative integer")
		}
	}
	return nil
}

func validateTypeDisplayMetadata(display DisplayMetadata) error {
	if display.Locale == "" {
		return fmt.Errorf("locale is required")
	}
	if display.Name == "" {
		return fmt.Errorf("name is required")
	}
	if display.Rendering != nil {
		if err := validateRenderingMetadata(*display.Rendering); err != nil {
			return err
		}
	}
	return nil
}

func validateClaimDisplayMetadata(display DisplayMetadata) error {
	if display.Locale == "" {
		return fmt.Errorf("locale is required")
	}
	label := display.Label
	if label == "" {
		label = display.Name
	}
	if label == "" {
		return fmt.Errorf("label is required")
	}
	return nil
}

func validateRenderingMetadata(rendering RenderingMetadata) error {
	if rendering.Simple == nil && len(rendering.SVGTemplates) == 0 {
		return fmt.Errorf("rendering must define at least one method")
	}
	if rendering.Simple != nil {
		if rendering.Simple.Logo != nil {
			if rendering.Simple.Logo.URI == "" {
				return fmt.Errorf("rendering.simple.logo.uri is required")
			}
			if rendering.Simple.Logo.URIIntegrity != "" {
				if err := validateIntegrityMetadata(rendering.Simple.Logo.URIIntegrity); err != nil {
					return fmt.Errorf("rendering.simple.logo.uri#integrity is invalid: %w", err)
				}
			}
		}
		if rendering.Simple.BackgroundImage != nil {
			if rendering.Simple.BackgroundImage.URI == "" {
				return fmt.Errorf("rendering.simple.background_image.uri is required")
			}
			if rendering.Simple.BackgroundImage.URIIntegrity != "" {
				if err := validateIntegrityMetadata(rendering.Simple.BackgroundImage.URIIntegrity); err != nil {
					return fmt.Errorf("rendering.simple.background_image.uri#integrity is invalid: %w", err)
				}
			}
		}
	}
	if len(rendering.SVGTemplates) > 0 {
		requireProps := len(rendering.SVGTemplates) > 1
		for i, tmpl := range rendering.SVGTemplates {
			if tmpl.URI == "" {
				return fmt.Errorf("rendering.svg_templates[%d].uri is required", i)
			}
			if tmpl.URIIntegrity != "" {
				if err := validateIntegrityMetadata(tmpl.URIIntegrity); err != nil {
					return fmt.Errorf("rendering.svg_templates[%d].uri#integrity is invalid: %w", i, err)
				}
			}
			if requireProps && len(tmpl.Properties) == 0 {
				return fmt.Errorf("rendering.svg_templates[%d].properties is required when multiple templates are present", i)
			}
		}
	}
	return nil
}
