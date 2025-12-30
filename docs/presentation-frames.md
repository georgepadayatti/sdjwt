# Presentation Frames (Holder's Perspective)

After receiving an SD-JWT, the holder uses **presentation frames** to select which claims to disclose to a verifier.

## 1. Selecting Top-Level Claims

Select specific top-level claims to disclose from a flat disclosure SD-JWT.

```go
// Assume SD-JWT was issued with these claims as SD:
// given_name, family_name, email, phone_number, birthdate

// Create holder from serialized SD-JWT
issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// See what claims are available to disclose
availableKeys, _ := h.GetPresentableKeys()
// Output: ["given_name", "family_name", "email", "phone_number", "birthdate"]

// Select only name claims to disclose
presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")

// Create presentation (without key binding)
presentation, _ := h.PresentWithFrameNoKB(presFrame)
// Result: Only given_name and family_name disclosures included
// email, phone_number, birthdate remain hidden
```

## 2. Selecting Nested Claims (Structured Disclosure)

Select specific claims from within a nested object.

```go
// Assume SD-JWT was issued with address sub-claims as SD:
// address.street_address, address.locality, address.region, address.country

issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// See available nested keys
availableKeys, _ := h.GetPresentableKeys()
// Output: ["given_name", "family_name", "address.street_address",
//          "address.locality", "address.region", "address.country"]

// Select only city and country from address
presFrame := sdjwt.NewPresentationFrame("given_name").
    WithNested("address", sdjwt.NewPresentationFrame("locality", "country"))

// Alternative: Build frame manually
presFrame := &sdjwt.PresentationFrame{
    Include: map[string]bool{
        "given_name": true,
    },
    Nested: map[string]*sdjwt.PresentationFrame{
        "address": {
            Include: map[string]bool{
                "locality": true,
                "country":  true,
            },
        },
    },
}

presentation, _ := h.PresentWithFrameNoKB(presFrame)
// Result: Discloses given_name, address.locality, address.country
// Hides: family_name, address.street_address, address.region
```

## 3. Selecting from Recursive Disclosure

When both the parent object AND its sub-claims are selectively disclosable, you must include the parent to reveal any children.

```go
// Assume SD-JWT was issued with:
// - "address" itself is SD (can hide entire address)
// - address sub-claims are also SD (street_address, locality, country)

issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// Available keys include both parent and children
availableKeys, _ := h.GetPresentableKeys()
// Output: ["given_name", "family_name", "address",
//          "address.street_address", "address.locality", "address.country"]

// Option A: Disclose address with only locality
// Must include "address" to reveal any sub-claims
presFrame := &sdjwt.PresentationFrame{
    Include: map[string]bool{
        "given_name": true,
        "address":    true,  // Required to reveal address object
    },
    Nested: map[string]*sdjwt.PresentationFrame{
        "address": {
            Include: map[string]bool{
                "locality": true,  // Only reveal city
            },
        },
    },
}

presentation, _ := h.PresentWithFrameNoKB(presFrame)
// Result: Verifier sees address: {locality: "Anytown"}
// street_address and country remain hidden within address

// Option B: Hide entire address
presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")
// Result: Address is completely hidden (not even visible as empty object)
```

## 4. Selecting Array Elements

Select specific elements from an array where individual elements are SD.

```go
// Assume SD-JWT was issued with nationalities array elements as SD:
// nationalities[0] = "US", nationalities[1] = "DE", nationalities[2] = "FR"

issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// Available keys use indices
availableKeys, _ := h.GetPresentableKeys()
// Output: ["given_name", "nationalities.0", "nationalities.1", "nationalities.2"]

// Disclose only the first nationality
presFrame := &sdjwt.PresentationFrame{
    Include: map[string]bool{
        "given_name": true,
    },
    Nested: map[string]*sdjwt.PresentationFrame{
        "nationalities": {
            Include: map[string]bool{
                "0": true,  // Only first element
            },
        },
    },
}

presentation, _ := h.PresentWithFrameNoKB(presFrame)
// Result: nationalities = ["US"]
// "DE" and "FR" remain hidden

// Disclose multiple elements
presFrame := &sdjwt.PresentationFrame{
    Nested: map[string]*sdjwt.PresentationFrame{
        "nationalities": {
            Include: map[string]bool{
                "0": true,
                "2": true,
            },
        },
    },
}
// Result: nationalities = ["US", "FR"] (indices 0 and 2)
```

## 5. Complex Nested Presentation

Handle deeply nested structures like OIDC Identity Assurance.

```go
// Assume SD-JWT with verified_claims structure where various nested claims are SD

issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// Build a complex presentation frame
presFrame := &sdjwt.PresentationFrame{
    Nested: map[string]*sdjwt.PresentationFrame{
        "verified_claims": {
            Nested: map[string]*sdjwt.PresentationFrame{
                "verification": {
                    Include: map[string]bool{
                        "trust_framework": true,
                    },
                },
                "claims": {
                    Include: map[string]bool{
                        "given_name":  true,
                        "family_name": true,
                        "birthdate":   true,
                    },
                    Nested: map[string]*sdjwt.PresentationFrame{
                        "address": {
                            Include: map[string]bool{
                                "locality": true,
                                "country":  true,
                            },
                        },
                    },
                },
            },
        },
    },
}

presentation, _ := h.PresentWithFrameNoKB(presFrame)
// Result: Only selected claims from the complex structure are disclosed
```

## 6. Disclose All Claims (Nil Frame)

Pass nil to include all available disclosures.

```go
issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// Disclose everything
presentation, _ := h.PresentWithFrameNoKB(nil)
// Result: All disclosures from the original SD-JWT are included
```

## 7. Presentation with Key Binding

Add holder proof of possession using Key Binding JWT. The key binding flow works as follows:

1. **Verifier** creates a `KeyBindingRequirement` with nonce and audience
2. **Verifier** sends this to the holder as part of a presentation request
3. **Holder** uses these values to create the Key Binding JWT
4. **Holder** sends the presentation back to the verifier
5. **Verifier** uses the same `KeyBindingRequirement` to verify the KB-JWT

```go
// === VERIFIER: Create key binding requirement ===
keyBinding := &verifier.KeyBindingRequirement{
    Nonce:    "xyz-random-nonce-123",           // Unique per request
    Audience: "https://verifier.example.org",   // Verifier's identifier
    MaxAge:   300,                              // Optional: max age in seconds
}
// Send keyBinding.Nonce and keyBinding.Audience to holder...

// === HOLDER: Create presentation with key binding ===
issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")

// Use the nonce and audience from verifier's request
kbOptions := holder.NewKeyBindingOptions(
    "https://verifier.example.org",  // Audience from verifier
    "xyz-random-nonce-123",          // Nonce from verifier
)

holderSigner, _ := signer.NewDefaultSigner()
presentation, _ := h.PresentWithFrame(
    presFrame,
    holderSigner,
    kbOptions,
)

serialized := holder.SerializePresentation(presentation)
// Send serialized presentation to verifier...

// === VERIFIER: Verify presentation with key binding ===
v := verifier.NewVerifier(issuerSigner)
requiredClaims := sdjwt.NewPresentationFrame("given_name", "family_name")

result, _ := v.VerifyWithKeyBinding(serialized, requiredClaims, keyBinding)
if result.Valid && *result.KeyBindingValid {
    fmt.Println("Presentation verified with holder binding!")
}
```

## 8. Inspecting Available Claims

Before creating a presentation, inspect what can be disclosed.

```go
issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// Get all claim keys that have disclosures (can be selectively revealed)
presentableKeys, _ := h.GetPresentableKeys()
fmt.Println("Can selectively disclose:", presentableKeys)
// Output: ["given_name", "family_name", "email", "address.street_address", ...]

// Get all claim keys (including non-SD claims in the JWT payload)
allKeys, _ := h.GetAllKeys()
fmt.Println("All claims:", allKeys)
// Output: ["sub", "iss", "iat", "given_name", "family_name", ...]

// Get the fully processed payload (all disclosures applied)
processed, _ := h.GetProcessedPayload()
fmt.Printf("Full payload: %+v\n", processed.Claims)
// Output shows all claims with their values
```

## 9. Presentation Frame Helper Methods

Use convenience methods to build presentation frames.

```go
// Method 1: NewPresentationFrame for top-level claims
frame := sdjwt.NewPresentationFrame("claim1", "claim2", "claim3")

// Method 2: Chain WithNested for nested claims
frame := sdjwt.NewPresentationFrame("given_name", "family_name").
    WithNested("address", sdjwt.NewPresentationFrame("city", "country")).
    WithNested("contact", sdjwt.NewPresentationFrame("email"))

// Method 3: AddClaim to existing frame
frame := sdjwt.NewPresentationFrame()
frame.AddClaim("given_name")
frame.AddClaim("family_name")

// Method 4: Merge multiple frames
frame1 := sdjwt.NewPresentationFrame("given_name")
frame2 := sdjwt.NewPresentationFrame("family_name")
merged := sdjwt.MergePresentationFrames(frame1, frame2)

// Method 5: Create from map (useful for dynamic frame construction)
frameMap := map[string]any{
    "given_name": true,
    "address": map[string]any{
        "city": true,
    },
}
frame := sdjwt.PresentationFrameFromMap(frameMap)
```
