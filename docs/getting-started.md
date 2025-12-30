# Getting Started

This guide covers installation and basic usage of the SD-JWT Go library.

## Installation

```bash
go get github.com/georgepadayatti/sdjwt
```

## Quick Start

### Basic SD-JWT Issuance

```go
package main

import (
    "fmt"

    "github.com/georgepadayatti/sdjwt/issuer"
    "github.com/georgepadayatti/sdjwt/sdjwt"
    "github.com/georgepadayatti/sdjwt/signer"
)

func main() {
    // Create issuer with the default signer (self-signed X.509)
    issuerSigner, _ := signer.NewDefaultSigner()
    iss := issuer.NewIssuer(issuerSigner)

    // Define claims
    claims := map[string]any{
        "given_name":  "John",
        "family_name": "Doe",
        "email":       "john@example.com",
    }

    // Create disclosure frame (which claims are selectively disclosable)
    frame := sdjwt.NewDisclosureFrame("given_name", "family_name", "email")

    // Issue SD-JWT
    sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)

    // Serialize
    fmt.Println(sdJWT.Serialize())
}
```

## Complete Issue and Verify Example

```go
package main

import (
    "fmt"

    "github.com/georgepadayatti/sdjwt/holder"
    "github.com/georgepadayatti/sdjwt/issuer"
    "github.com/georgepadayatti/sdjwt/sdjwt"
    "github.com/georgepadayatti/sdjwt/signer"
    "github.com/georgepadayatti/sdjwt/verifier"
)

func main() {
    // Create signers
    issuerSigner, _ := signer.NewDefaultSigner()
    holderSigner, _ := signer.NewDefaultSigner()

    // === ISSUER: Create SD-JWT ===
    iss := issuer.NewIssuer(issuerSigner)

    claims := map[string]any{
        "sub":          "user_42",
        "given_name":   "John",
        "family_name":  "Doe",
        "email":        "john@example.com",
        "phone_number": "+1-202-555-0101",
        "address": map[string]any{
            "street_address": "123 Main St",
            "locality":       "Anytown",
            "country":        "US",
        },
    }

    // Structured disclosure with nested address claims
    frame := &sdjwt.DisclosureFrame{
        SD: []string{"given_name", "family_name", "email", "phone_number"},
        Nested: map[string]*sdjwt.DisclosureFrame{
            "address": {
                SD: []string{"street_address", "locality", "country"},
            },
        },
    }

    sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
    serialized := sdJWT.Serialize()
    fmt.Println("Issued SD-JWT with", len(sdJWT.Disclosures), "disclosures")

    // === HOLDER: Create Presentation ===
    h, _ := holder.ParseAndCreateHolder(serialized, issuerSigner, nil)

    // Select only name and city to disclose
    presFrame := sdjwt.NewPresentationFrame("given_name", "family_name").
        WithNested("address", sdjwt.NewPresentationFrame("locality"))

    kbOptions := holder.KeyBindingOptions{
        Audience: "https://verifier.example.org",
        Nonce:    "random-nonce-123",
    }

    presentation, _ := h.PresentWithFrame(presFrame, holderSigner, kbOptions)
    presentationStr := holder.SerializePresentation(presentation)
    fmt.Println("Created presentation with selected disclosures")

    // === VERIFIER: Verify Presentation ===
    v := verifier.NewVerifier(issuerSigner)

    // Required claims as presentation frame
    requiredClaims := sdjwt.NewPresentationFrame("given_name", "family_name")

    // Key binding requirement (same nonce/audience sent to holder)
    keyBinding := &verifier.KeyBindingRequirement{
        Nonce:    "random-nonce-123",
        Audience: "https://verifier.example.org",
        MaxAge:   300, // Optional: max age in seconds
    }

    result, _ := v.VerifyWithKeyBinding(presentationStr, requiredClaims, keyBinding)
    if result.Valid {
        fmt.Println("Verification successful!")
        fmt.Println("Disclosed claims:", result.DisclosedClaims)
        // Output: map[family_name:Doe given_name:John address:map[locality:Anytown]]
    }
}
```

## Next Steps

- [Disclosure Patterns](disclosure-patterns.md) - Learn about different SD-JWT disclosure patterns
- [Presentation Frames](presentation-frames.md) - How holders create presentations
- [Package Reference](packages.md) - Detailed package documentation
