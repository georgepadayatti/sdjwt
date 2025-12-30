# ETSI EAA - Electronic Attestation of Attributes

The `sdjwtvc` package includes support for ETSI TS 119 472-1 v1.1.1 Electronic Attestation of Attributes (EAA), which profiles SD-JWT VC for use in the European Union's eIDAS 2.0 framework.

## EAA Categories

- **QEAA (Qualified EAA)**: Issued by qualified trust service providers
- **PuB-EAA**: Issued by or on behalf of public bodies responsible for authentic sources
- **Regular EAA**: Standard EAA without QEAA/PuB-EAA requirements

## Basic Usage

```go
import (
    "github.com/georgepadayatti/sdjwt/sdjwtvc"
    "github.com/georgepadayatti/sdjwt/signer"
)

// Create a QEAA issuer with X.509 certificate
issuerSigner, _ := signer.NewDefaultSigner()
eaaIssuer, _ := sdjwtvc.NewEAAIssuer(sdjwtvc.EAAIssuerConfig{
    Category:              sdjwtvc.EAACategoryQEAA,
    IssuerID:              "https://issuer.example.com",
    IssuingAuthority:      "German Federal Authority",
    IssuingCountry:        "DE",
    IssuerRegistrationID:  "NTDE-HRB12345",
    Signer:                issuerSigner,
    SigningCertificate:    issuerSigner.Certificate(),
    SigningCertificateURL: "https://issuer.example.com/cert",
})

// Define claims
claims := map[string]any{
    "given_name":  "Max",
    "family_name": "Mustermann",
    "birthdate":   "1990-01-15",
}

// Create disclosure frame
frame := sdjwt.NewDisclosureFrame("given_name", "family_name", "birthdate")

// Issue EAA
now := time.Now()
eaa, _ := eaaIssuer.Issue(claims, frame, sdjwtvc.EAAIssueOptions{
    VCT:            "https://example.com/credentials/IdentityCredential",
    VCTIntegrity:   "sha256-abcdef123456",
    JTI:            "urn:uuid:12345678-1234-1234-1234-123456789abc",
    Subject:        "urn:user:max.mustermann",
    NotBefore:      now,
    ExpirationTime: now.Add(365 * 24 * time.Hour),
    Status: &sdjwtvc.EAAStatus{
        Type:    sdjwtvc.StatusTypeTokenStatusList,
        Purpose: "revocation",
        Index:   42,
        URI:     "https://issuer.example.com/status/1",
    },
})
```

## ETSI EAA-specific Claims

| Claim | Description | Required |
|-------|-------------|----------|
| `vct` | Verifiable Credential Type URI | Yes |
| `vct#integrity` | VCT document hash | Yes |
| `jti` | EAA identifier | Yes |
| `iss` | Issuer URI | Yes |
| `nbf` | Technical validity start | Yes |
| `exp` | Technical validity end | Yes |
| `category` | EAA category URN | QEAA/PuB-EAA only |
| `issuing_authority` | Issuer name | QEAA/PuB-EAA only |
| `issuing_country` | EU Member country code | QEAA/PuB-EAA only |
| `iss_reg_id` | Issuer registration ID | When applicable |
| `sub` | Subject identifier | Either sub or also_known_as |
| `also_known_as` | Subject pseudonym | Either sub or also_known_as |
| `adm_nbf` / `adm_exp` | Administrative validity period | Optional (both or neither) |
| `oneTime` | One-time use indicator (null) | Optional |
| `shortLived` | Short-lived indicator (null) | Optional |
| `status` | Revocation status reference | QEAA/PuB-EAA required |
| `subAttrs` | Attributes for other entities | Optional |

## ETSI Status Structure

ETSI requires a different status structure than standard SD-JWT VC:

```go
status := &sdjwtvc.EAAStatus{
    Type:    "TokenStatusList",  // or "BitstringStatusListEntry"
    Purpose: "revocation",
    Index:   42,
    URI:     "https://issuer.example.com/status/1",
}
```

## X.509 Certificate Support

ETSI EAA supports X.509 certificates in JWT headers and CNF claim:

### JWT Headers
```go
eaaIssuer, _ := sdjwtvc.NewEAAIssuer(sdjwtvc.EAAIssuerConfig{
    // ...
    SigningCertificate:     cert,              // x5c header
    SigningCertificateChain: []*x509.Certificate{cert, intermediate},
    SigningCertificateURL:  "https://issuer.example.com/cert",  // x5u header
    // x5t#S256 is computed automatically
})
```

### CNF Claim (Holder Key Binding)
```go
// CNF claim with X.509 certificate
cnf := sdjwtvc.EAACNFClaim{
    X5C: []string{base64EncodedCert},  // Certificate chain
}

// Or with URL and thumbprint
cnf := sdjwtvc.EAACNFClaim{
    X5U:     "https://example.com/holder/cert",
    X5TS256: "thumbprint-base64url",
}
```

## EAA Validation

```go
// Validate EAA payload
err := sdjwtvc.ValidateEAA(payload, nil)

// Validate with options
qeaaCategory := sdjwtvc.EAACategoryQEAA
err := sdjwtvc.ValidateEAA(payload, &sdjwtvc.EAAValidationOptions{
    ExpectedCategory:    &qeaaCategory,
    SkipExpirationCheck: false,
    AllowedClockSkew:    time.Minute,
})

// Check selective disclosure rules for ETSI claims
canSD := sdjwtvc.IsEAAClaimSelectivelyDisclosable("given_name")  // true
cannotSD := sdjwtvc.IsEAAClaimSelectivelyDisclosable("jti")      // false
```

## Pseudonym EAA

Use `also_known_as` instead of `sub` for privacy:

```go
eaa, _ := eaaIssuer.Issue(claims, frame, sdjwtvc.EAAIssueOptions{
    VCT:            "https://example.com/credentials/Membership",
    VCTIntegrity:   "sha256-abc123",
    JTI:            "urn:uuid:...",
    Pseudonym:      "anon-member-xyz789",  // Uses also_known_as instead of sub
    NotBefore:      now,
    ExpirationTime: now.Add(365 * 24 * time.Hour),
})
```

## One-Time and Short-Lived EAA

```go
eaa, _ := eaaIssuer.Issue(claims, frame, sdjwtvc.EAAIssueOptions{
    VCT:            "https://example.com/credentials/OneTimeToken",
    VCTIntegrity:   "sha256-onetime123",
    JTI:            "urn:uuid:...",
    Subject:        "urn:user:temp123",
    NotBefore:      now,
    ExpirationTime: now.Add(1 * time.Hour),  // Short-lived
    OneTime:        true,   // oneTime claim with JSON null value
    ShortLived:     true,   // shortLived claim with JSON null value
})
```

## PuB-EAA Example

```go
issuerSigner, _ := signer.NewDefaultSigner()
pubEAAIssuer, _ := sdjwtvc.NewEAAIssuer(sdjwtvc.EAAIssuerConfig{
    Category:              sdjwtvc.EAACategoryPuBEAA,
    IssuerID:              "https://education.example.gov",
    IssuingAuthority:      "Ministry of Education",
    IssuingCountry:        "FR",
    IssuerRegistrationID:  "FRMIN-EDU-001",
    Signer:                issuerSigner,
    SigningCertificate:    issuerSigner.Certificate(),
    SigningCertificateURL: "https://education.example.gov/certs/signing.pem",
})

// Educational credential
eduClaims := map[string]any{
    "degree_type":    "Master of Science",
    "degree_field":   "Computer Science",
    "institution":    "University of Paris",
    "graduation_date": "2023-06-15",
}

pubEAA, _ := pubEAAIssuer.Issue(eduClaims, frame, sdjwtvc.EAAIssueOptions{
    VCT:            "https://example.eu/credentials/EducationCredential",
    VCTIntegrity:   "sha256-edu789xyz",
    JTI:            "urn:uuid:...",
    Subject:        "urn:fr:education:student:12345",
    NotBefore:      now,
    ExpirationTime: now.Add(10 * 365 * 24 * time.Hour),
    Status: &sdjwtvc.EAAStatus{
        Type:    sdjwtvc.StatusTypeBitstringStatusList,
        Purpose: "revocation",
        Index:   100,
        URI:     "https://education.example.gov/status/degrees/1",
    },
})
```

## ETSI Selective Disclosure Rules

Claims that **MUST NOT** be selectively disclosed:
- `jti`, `vct`, `vct#integrity`
- `iss`, `nbf`, `exp`
- `category`, `issuing_authority`, `issuing_country`, `iss_reg_id`
- `cnf`, `status`
- `adm_nbf`, `adm_exp`, `oneTime`, `shortLived`

Claims that **CAN** be selectively disclosed:
- `sub`, `also_known_as`
- `iat`
- All subject attribute claims (e.g., `given_name`, `birthdate`)
- `subAttrs`
