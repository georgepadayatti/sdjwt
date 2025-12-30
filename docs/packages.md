# Package Reference

This document provides detailed documentation for each package in the SD-JWT library.

## sdjwt - Core Types and Operations

The `sdjwt` package provides core types and utilities for SD-JWT operations.

```go
import "github.com/georgepadayatti/sdjwt/sdjwt"

// Parse an SD-JWT string
sdJWT, kbJWT, _ := sdjwt.Parse(serializedSDJWT, "sha-256")

// Create a disclosure frame for selective disclosure
frame := sdjwt.NewDisclosureFrame("claim1", "claim2")

// With nested claims
frame := sdjwt.NewDisclosureFrameWithNested(
    []string{"name"},
    map[string]*sdjwt.DisclosureFrame{
        "address": sdjwt.NewDisclosureFrame("street", "city"),
    },
)

// With decoy digests
frame := sdjwt.NewDisclosureFrameWithDecoys([]string{"name"}, 3)

// Create a presentation frame for selecting claims to disclose
presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")

// Serialize to different formats
compact := sdJWT.Serialize()                    // Compact serialization
flatJSON, _ := sdJWT.SerializeFlattenJSON()     // Flattened JSON
generalJSON, _ := sdJWT.SerializeGeneralJSON()  // General JSON
```

## issuer - Creating SD-JWTs

The `issuer` package provides functionality for creating SD-JWTs.

```go
import (
    "github.com/georgepadayatti/sdjwt/issuer"
    "github.com/georgepadayatti/sdjwt/signer"
)

// Create an issuer with the default signer (self-signed X.509)
issuerSigner, _ := signer.NewDefaultSigner()
iss := issuer.NewIssuer(issuerSigner)

// Or create an issuer with custom signer (for HSM/KMS)
iss := issuer.NewIssuer(customSigner)

// Define claims
claims := map[string]any{
    "given_name":  "John",
    "family_name": "Doe",
    "address": map[string]any{
        "street": "123 Main St",
        "city":   "Anytown",
    },
}

frame := &sdjwt.DisclosureFrame{
    SD: []string{"given_name", "family_name"},
    Nested: map[string]*sdjwt.DisclosureFrame{
        "address": {SD: []string{"street"}},
    },
}

sdJWT, _ := iss.IssueWithFrame(claims, frame, &issuer.IssueOptions{
    HashAlgorithm: "sha-256",
    Type:          "sd+jwt",
})
```

## holder - Managing and Presenting Credentials

The `holder` package provides functionality for receiving SD-JWTs and creating presentations.

```go
import (
    "github.com/georgepadayatti/sdjwt/holder"
    "github.com/georgepadayatti/sdjwt/signer"
)

// Parse and create a holder from serialized SD-JWT
issuerSigner, _ := signer.NewDefaultSigner()
h, _ := holder.ParseAndCreateHolder(serializedSDJWT, issuerSigner, nil)

// Or create from an existing SDJWT struct
h := holder.NewHolder(sdJWT)

// View available claims that can be disclosed
availableKeys, _ := h.GetPresentableKeys()

// Get processed payload with all disclosures applied
processed, _ := h.GetProcessedPayload()

// Create presentation frame to select claims to disclose
presFrame := sdjwt.NewPresentationFrame("given_name", "family_name")

// For nested claims
presFrame := sdjwt.NewPresentationFrame("given_name").
    WithNested("address", sdjwt.NewPresentationFrame("street", "city"))

// Create presentation with key binding
kbOptions := holder.KeyBindingOptions{
    Audience: "https://verifier.example.org",
    Nonce:    "random-nonce-123",
}
holderSigner, _ := signer.NewDefaultSigner()
presentation, _ := h.PresentWithFrame(
    presFrame,
    holderSigner,
    kbOptions,
)

// Create presentation without key binding
presentationNoKB, _ := h.PresentWithFrameNoKB(presFrame)

// Serialize presentation
serialized := holder.SerializePresentation(presentation)
```

## verifier - Validating Presentations

The `verifier` package provides functionality for verifying SD-JWT presentations.

```go
import (
    "github.com/georgepadayatti/sdjwt/verifier"
    "github.com/georgepadayatti/sdjwt/signer"
)

// Create a verifier with the issuer's signer (for public key access)
issuerSigner, _ := signer.NewDefaultSigner()
v := verifier.NewVerifier(issuerSigner)

// Required claims as presentation frame
requiredClaims := sdjwt.NewPresentationFrame("given_name", "family_name")

// Key binding requirement (provided to holder for crafting KB-JWT)
keyBinding := &verifier.KeyBindingRequirement{
    Nonce:    "random-nonce-123",
    Audience: "https://verifier.example.org",
    MaxAge:   300, // 5 minutes
}

// Verify without key binding
result, _ := v.Verify(serializedPresentation, requiredClaims)

// Verify with key binding
result, _ := v.VerifyWithKeyBinding(serializedPresentation, requiredClaims, keyBinding)

// Check result
if result.Valid {
    fmt.Println("Disclosed claims:", result.DisclosedClaims)
    fmt.Println("Processed payload:", result.ProcessedPayload)
}
```

## signer - Custom Signing Interface

The `signer` package provides an interface for custom signing implementations.

```go
import "github.com/georgepadayatti/sdjwt/signer"

// The Signer interface for custom implementations
type Signer interface {
    // Sign signs the JWT content and returns the signature
    Sign(signingInput string) ([]byte, error)
    // Algorithm returns the JWT "alg" header value (e.g., "ES256")
    Algorithm() string
    // PublicKey returns the public key corresponding to the signing key
    PublicKey() crypto.PublicKey
    // Certificate returns the signing certificate if available
    Certificate() *x509.Certificate
    // CertificateChain returns the full certificate chain if available
    CertificateChain() []*x509.Certificate
}

// Use DefaultSigner for local key signing
s, _ := signer.NewDefaultSigner()

// Create issuer with custom signer
iss := issuer.NewIssuer(customSigner)

// Create key binding JWT with custom signer
kbJWT, _ := holder.CreateKeyBindingJWT(sdj, holderSigner, kbOptions)

// Create VC issuer with custom signer
vcIssuer := sdjwtvc.NewVCIssuerWithSigner("https://issuer.example.com", customSigner, "sha-256")
```

For detailed custom signer documentation, see [Custom Signer Guide](custom-signer.md).

## statuslist - Credential Revocation

The `statuslist` package implements JWT Status List for credential revocation.

```go
import "github.com/georgepadayatti/sdjwt/statuslist"

// Create a status list (10000 entries, 1 bit per status)
sl, _ := statuslist.NewStatusList(10000, statuslist.Bits1)

// Set status for specific credentials
sl.SetStatus(42, statuslist.StatusInvalid)   // Revoke credential at index 42
sl.SetStatus(100, statuslist.StatusInvalid)  // Revoke credential at index 100

// Check status
status, _ := sl.GetStatus(42)
if status == statuslist.StatusValid {
    fmt.Println("Credential is valid")
} else {
    fmt.Println("Credential is revoked")
}

// Create a status list token
token, _ := statuslist.NewStatusListToken(
    "https://issuer.example.com",
    "https://issuer.example.com/status/1",
    sl,
    time.Now().Unix(),
    time.Now().Add(24 * time.Hour).Unix(),
)

// Sign and serialize the token
issuerSigner, _ := signer.NewDefaultSigner()
signedToken, _ := token.Sign(issuerSigner, nil)

// Check credential status against the status list
vcPayload := map[string]any{
    "status": map[string]any{
        "status_list": map[string]any{
            "idx": 42,
            "uri": "https://issuer.example.com/status/1",
        },
    },
}
valid, _ := sdjwtvc.CheckStatus(vcPayload, token, 10000)
```
