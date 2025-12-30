# SD-JWT Disclosure Patterns

This guide demonstrates the different disclosure patterns supported by the library, matching RFC 9901 examples.

## 1. Flat Disclosure (RFC 9901 Section 6.1)

Disclose an entire nested object as a single unit. The holder can either reveal the complete address or nothing.

```go
claims := map[string]any{
    "sub":          "user_42",
    "given_name":   "John",
    "family_name":  "Doe",
    "email":        "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": map[string]any{
        "street_address": "123 Main St",
        "locality":       "Anytown",
        "region":         "Anystate",
        "country":        "US",
    },
    "birthdate": "1940-01-01",
}

// Make address SD as a whole (flat disclosure)
frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name", "email", "phone_number", "address", "birthdate"},
    // No nested frame for address - disclosed as single unit
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: 6 disclosures, address contains full object when revealed
```

## 2. Structured Disclosure (RFC 9901 Section 6.2)

Disclose individual sub-claims within a nested object separately. The holder can reveal specific address fields.

```go
claims := map[string]any{
    "sub":          "user_42",
    "given_name":   "John",
    "family_name":  "Doe",
    "address": map[string]any{
        "street_address": "123 Main St",
        "locality":       "Anytown",
        "region":         "Anystate",
        "country":        "US",
    },
}

// Make address sub-claims individually SD
frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name"},
    Nested: map[string]*sdjwt.DisclosureFrame{
        "address": {
            SD: []string{"street_address", "locality", "region", "country"},
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: address object visible in JWT, but its fields are in _sd array
// Holder can selectively reveal street_address without revealing locality
```

## 3. Recursive Disclosure (RFC 9901 Section 6.3)

Both the parent object AND its sub-claims are selectively disclosable. The holder can hide the entire address, or reveal it with selected fields.

```go
claims := map[string]any{
    "sub":          "user_42",
    "given_name":   "John",
    "family_name":  "Doe",
    "address": map[string]any{
        "street_address": "123 Main St",
        "locality":       "Anytown",
        "region":         "Anystate",
        "country":        "US",
    },
}

// Make address itself SD, AND its sub-claims also SD
frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name", "address"}, // address itself is SD
    Nested: map[string]*sdjwt.DisclosureFrame{
        "address": {
            SD: []string{"street_address", "locality", "region", "country"},
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: 10 disclosures (6 top-level including address + 4 address sub-claims)
// address disclosure contains object with its own _sd array
```

## 4. Array Element Disclosure (RFC 9901 Section 5)

Disclose individual array elements separately. The holder can reveal specific nationalities.

```go
claims := map[string]any{
    "sub":           "user_42",
    "given_name":    "John",
    "family_name":   "Doe",
    "nationalities": []any{"US", "DE"},
}

// Make individual array elements SD
frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name"},
    Nested: map[string]*sdjwt.DisclosureFrame{
        "nationalities": {
            SD: []string{"0", "1"}, // Array indices as strings
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: nationalities array contains {"...": "digest"} placeholders
// Each element can be revealed independently
```

## 5. Full Array Disclosure

Disclose the entire array as a single unit.

```go
claims := map[string]any{
    "sub":           "user_42",
    "given_name":    "John",
    "family_name":   "Doe",
    "nationalities": []any{"US", "DE"},
}

// Make entire array SD (not individual elements)
frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name", "nationalities"},
    // No nested frame for nationalities
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: 3 disclosures, nationalities disclosure contains ["US", "DE"]
```

## 6. Mixed Array Content

Some array elements are SD, others are always visible.

```go
claims := map[string]any{
    "sub":    "user_42",
    "emails": []any{"primary@example.com", "secondary@example.com", "backup@example.com"},
}

// Only first and third elements are SD
frame := &sdjwt.DisclosureFrame{
    Nested: map[string]*sdjwt.DisclosureFrame{
        "emails": {
            SD: []string{"0", "2"}, // First and third only
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: emails = [{"...": "digest"}, "secondary@example.com", {"...": "digest"}]
// secondary@example.com is always visible
```

## 7. Decoy Digests (RFC 9901 Appendix A.1)

Add decoy digests to hide the true number of claims.

```go
claims := map[string]any{
    "sub":        "user_42",
    "given_name": "John",
}

// Add 3 decoy digests at top level
frame := &sdjwt.DisclosureFrame{
    SD:      []string{"given_name"},
    SDDecoy: 3,
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: _sd array has 4 entries (1 real + 3 decoys)
// Verifier cannot tell how many real claims exist
```

## 8. Nested Decoy Digests

Add decoys at nested levels for additional privacy.

```go
claims := map[string]any{
    "sub": "user_42",
    "address": map[string]any{
        "street_address": "123 Main St",
        "locality":       "Anytown",
    },
}

// Add decoys in the nested address object
frame := &sdjwt.DisclosureFrame{
    Nested: map[string]*sdjwt.DisclosureFrame{
        "address": {
            SD:      []string{"street_address"},
            SDDecoy: 2,
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: address._sd has 3 entries (1 real + 2 decoys)
// locality remains visible (not in SD list)
```

## 9. Complex Nested Structure (RFC 9901 Appendix A.2)

Handle deeply nested structures like OIDC Identity Assurance verified_claims.

```go
claims := map[string]any{
    "sub": "user_42",
    "verified_claims": map[string]any{
        "verification": map[string]any{
            "trust_framework": "de_aml",
            "evidence": []any{
                map[string]any{
                    "type":   "document",
                    "method": "pipp",
                    "document": map[string]any{
                        "type": "idcard",
                    },
                },
            },
        },
        "claims": map[string]any{
            "given_name":  "Max",
            "family_name": "Mustermann",
            "birthdate":   "1956-01-28",
            "place_of_birth": map[string]any{
                "country":  "DE",
                "locality": "Musterstadt",
            },
            "nationalities": []any{"DE"},
            "address": map[string]any{
                "locality":       "Maxstadt",
                "postal_code":    "12344",
                "country":        "DE",
                "street_address": "Weidenstraße 22",
            },
        },
    },
}

// Complex nested disclosure frame
frame := &sdjwt.DisclosureFrame{
    Nested: map[string]*sdjwt.DisclosureFrame{
        "verified_claims": {
            Nested: map[string]*sdjwt.DisclosureFrame{
                "verification": {
                    SD: []string{"trust_framework"},
                    Nested: map[string]*sdjwt.DisclosureFrame{
                        "evidence": {
                            SD: []string{"0"}, // First evidence item is SD
                        },
                    },
                },
                "claims": {
                    SD: []string{
                        "given_name", "family_name", "birthdate",
                        "place_of_birth", "nationalities", "address",
                    },
                },
            },
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: 8 disclosures across multiple nesting levels
```

## 10. Deep Nesting

SD-JWT supports arbitrary nesting depth.

```go
claims := map[string]any{
    "sub": "user_42",
    "level1": map[string]any{
        "level2": map[string]any{
            "level3": map[string]any{
                "level4": map[string]any{
                    "secret": "deep_value",
                },
            },
        },
    },
}

// Make the deepest claim SD
frame := &sdjwt.DisclosureFrame{
    Nested: map[string]*sdjwt.DisclosureFrame{
        "level1": {
            Nested: map[string]*sdjwt.DisclosureFrame{
                "level2": {
                    Nested: map[string]*sdjwt.DisclosureFrame{
                        "level3": {
                            Nested: map[string]*sdjwt.DisclosureFrame{
                                "level4": {
                                    SD: []string{"secret"},
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
// Result: level4 object has _sd array with secret's digest
```
