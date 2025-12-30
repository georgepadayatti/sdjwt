# SD-JWT Verifiable Credentials

The `sdjwtvc` package implements SD-JWT based Verifiable Credentials per draft-ietf-oauth-sd-jwt-vc-13.

## Basic Usage

```go
import (
    "github.com/georgepadayatti/sdjwt/sdjwtvc"
    "github.com/georgepadayatti/sdjwt/signer"
)

// Create a VC issuer
issuerSigner, _ := signer.NewDefaultSigner()
vcIssuer, _ := sdjwtvc.NewVCIssuer(sdjwtvc.IssuerConfig{
    IssuerID:      "https://issuer.example.com",
    Signer:        issuerSigner,
    HashAlgorithm: "sha-256",
})

// Define credential claims
claims := map[string]any{
    "given_name":  "John",
    "family_name": "Doe",
    "birthdate":   "1990-01-01",
    "address": map[string]any{
        "street":  "123 Main St",
        "city":    "Anytown",
        "country": "US",
    },
}

// Define which claims are selectively disclosable
frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name", "birthdate"},
    Nested: map[string]*sdjwt.DisclosureFrame{
        "address": {SD: []string{"street", "city"}},
    },
}

// Issue the VC
exp := time.Now().Add(365 * 24 * time.Hour)
vc, _ := vcIssuer.Issue(claims, frame, sdjwtvc.VCIssueOptions{
    VCT:            "https://example.com/credentials/IdentityCredential",
    VCTIntegrity:   "sha256-abcdef123456",
    Subject:        "did:example:12345",
    ExpirationTime: &exp,
    Status: &sdjwtvc.StatusListReference{
        Index: 42,
        URI:   "https://issuer.example.com/status/1",
    },
})
```

## Validation

```go
// Validate a VC payload
err := sdjwtvc.ValidateVC(payload)

// Validate with options
err := sdjwtvc.ValidateVCWithOptions(payload, &sdjwtvc.ValidationOptions{
    SkipExpirationCheck: false,
    AllowedClockSkew:    time.Minute,
})

// Check selective disclosure rules
canSD := sdjwtvc.IsClaimSelectivelyDisclosable("given_name")    // true
mustNotSD := sdjwtvc.MustNotBeSelectivelyDisclosed("vct")       // true
maySD := sdjwtvc.MayBeSelectivelyDisclosed("sub")               // true
```

## Verification

```go
// Verify a VC presentation with key binding
result, err := sdjwtvc.VerifySDJWTVCWithKeyBinding(
    serializedPresentation,
    issuerSigner,
    requiredClaims,
    keyBinding,
    &sdjwtvc.VCVerificationOptions{
        Validation: &sdjwtvc.ValidationOptions{
            SkipExpirationCheck: false,
        },
        CheckStatus:     true,
        StatusListToken: statusToken,
        StatusListSize:  10000,
    },
)
if err != nil {
    // verification failed
}
if result.Valid {
    fmt.Println("Verified VC payload:", result.ProcessedPayload)
}
```

## Type Metadata Validation

```go
if err := sdjwtvc.ValidateVCTMetadata(&metadata); err != nil {
    // invalid metadata
}
```

## Selective Disclosure Rules (Section 3.2.2.2)

| Claim | Can be SD | Must NOT be SD |
|-------|-----------|----------------|
| `vct` | No | Yes |
| `iss` | No | Yes |
| `exp` | No | Yes |
| `nbf` | No | Yes |
| `cnf` | No | Yes |
| `status` | No | Yes |
| `sub` | Yes | No |
| `iat` | Yes | No |
| Custom claims | Yes | No |

## VCT Metadata

Define credential type metadata for display and validation:

```go
metadata := sdjwtvc.VCTMetadata{
    VCT:         "https://example.com/credentials/IdentityCredential",
    Name:        "Identity Credential",
    Description: "A credential for identity verification",
    Extends:     []string{"https://example.com/credentials/BaseCredential"},
    Schema:      "https://example.com/schemas/identity.json",
    Display: []sdjwtvc.DisplayMetadata{
        {
            Locale:      "en-US",
            Name:        "Identity Credential",
            Description: "Verify your identity",
            Rendering: &sdjwtvc.RenderingMetadata{
                Simple: &sdjwtvc.SimpleRendering{
                    Logo: &sdjwtvc.LogoMetadata{
                        URI:     "https://example.com/logo.png",
                        AltText: "Example Logo",
                    },
                    BackgroundColor: "#1E90FF",
                    TextColor:       "#FFFFFF",
                },
            },
        },
    },
    Claims: []sdjwtvc.ClaimMetadata{
        {
            Path:      sdjwtvc.NewClaimPath("given_name"),
            Mandatory: true,
            SD:        sdjwtvc.SDAlways,
            Display: []sdjwtvc.DisplayMetadata{
                {Locale: "en-US", Label: "First Name"},
            },
        },
        {
            Path: sdjwtvc.NewClaimPath("address", "street"),
            SD:   sdjwtvc.SDAllowed,
        },
    },
}
```

## Claim Path Notation (Section 9.1)

```go
// Simple claim
path := sdjwtvc.NewClaimPath("given_name")           // ["given_name"]

// Nested claim
path := sdjwtvc.NewClaimPath("address", "street")    // ["address", "street"]

// Array index
path := sdjwtvc.NewClaimPath("nationalities", 0)     // ["nationalities", 0]

// Wildcard (any array element or property)
path := sdjwtvc.NewClaimPath("nationalities", nil)   // ["nationalities", null]

// Human-readable string representation
path.String() // "address.street" or "nationalities.*" or "nationalities.[0]"
```

## Media Type and Type Header

```go
// Media type for SD-JWT VC
sdjwtvc.MediaType  // "application/dc+sd-jwt"

// Type header value
sdjwtvc.TypeHeader // "dc+sd-jwt"
```
