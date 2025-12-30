# SD-JWT Go Library

A comprehensive Go implementation of [RFC 9901 - Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/rfc9901/) and [SD-JWT-based Verifiable Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/).

> **Disclaimer:** This is a fun experiment; use at your peril. It is not intended for production use.

## Features

- **RFC 9901 Compliant**: Full implementation of Selective Disclosure JWT
- **SD-JWT VC (draft-13)**: Complete support for SD-JWT based Verifiable Credentials
- **ETSI TS 119 472-1**: Support for EU Electronic Attestation of Attributes (QEAA, PuB-EAA)
- **Frame-based API**: Intuitive disclosure frame pattern for selective disclosure
- **Custom Signer Interface**: Support for HSMs, cloud KMS, and external signing services
- **Default Signer**: Built-in self-signed X.509 signer for local development
- **X.509 Certificate Support**: Full X.509 support for ETSI EAA (x5c, x5u, x5t#S256)
- **Status List**: JWT Status List for credential revocation (draft-ietf-oauth-status-list)
- **Key Binding**: Full support for holder key binding with KB-JWT
- **Multiple Serialization Formats**: Compact, Flattened JSON, and General JSON
- **Comprehensive Hash Support**: SHA-256, SHA-384, SHA-512

## Installation

```bash
go get github.com/georgepadayatti/sdjwt
```

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/georgepadayatti/sdjwt/issuer"
    "github.com/georgepadayatti/sdjwt/sdjwt"
    "github.com/georgepadayatti/sdjwt/signer"
)

func main() {
    // Create a default signer (self-signed X.509)
    issuerSigner, _ := signer.NewDefaultSigner()

    // Create issuer
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

## Documentation

Detailed documentation is available in the [docs](docs/) folder:

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and basic usage |
| [Disclosure Patterns](docs/disclosure-patterns.md) | Flat, structured, recursive, array disclosure |
| [Presentation Frames](docs/presentation-frames.md) | How holders create presentations |
| [Package Reference](docs/packages.md) | Detailed package documentation |
| [SD-JWT VC](docs/sdjwtvc.md) | Verifiable Credentials (draft-13) |
| [ETSI EAA](docs/etsi-eaa.md) | Electronic Attestation of Attributes |
| [Custom Signer](docs/custom-signer.md) | HSM/KMS integration |
| [Serialization](docs/serialization.md) | Compact, JSON serialization formats |
| [Testing](docs/testing.md) | Test coverage and running tests |

## Package Overview

| Package | Description |
|---------|-------------|
| `sdjwt` | Core types and operations (SDJWT, Disclosure, frames) |
| `issuer` | Create SD-JWTs with disclosure frames |
| `holder` | Receive SD-JWTs and create presentations |
| `verifier` | Validate presentations and verify signatures |
| `sdjwtvc` | SD-JWT Verifiable Credentials (draft-13) |
| `signer` | Custom signer interface for HSM/KMS |
| `statuslist` | JWT Status List for credential revocation |

## Examples

The `examples/` folder contains comprehensive demos organized by feature:

| File | Description |
|------|-------------|
| `basic.go` | Basic SD-JWT flow (issue, present, verify) |
| `nested.go` | Nested claims with selective disclosure |
| `arrays.go` | Array element selective disclosure |
| `serialization.go` | Serialization formats |
| `sdjwtvc.go` | SD-JWT VC (Verifiable Credentials) |
| `statuslist.go` | Status list for credential revocation |
| `metadata.go` | VCT metadata structures |
| `custom_signer.go` | Custom signer interface (HSM/KMS) |
| `etsi_eaa.go` | ETSI TS 119 472-1 EAA |

Run the examples:

```bash
go run ./examples
```

## Supported Algorithms

### Signing Algorithms
- ECDSA: ES256, ES384, ES512
- RSA: RS256, RS384, RS512
- RSA-PSS: PS256, PS384, PS512
- EdDSA

### Hash Algorithms
- SHA-256 (default)
- SHA-384
- SHA-512

## Standards Compliance

This library implements:

- [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) - Selective Disclosure for JWTs (SD-JWT)
- [draft-ietf-oauth-sd-jwt-vc-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) - SD-JWT-based Verifiable Credentials
- [draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) - Token Status List
- [ETSI TS 119 472-1 v1.1.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947201/01.01.01_60/ts_11947201v010101p.pdf) - Profiles for Electronic Attestation of Attributes; Part 1: General requirements

## Running Tests

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test ./... -v

# Run tests for a specific package
go test ./issuer/... -v
go test ./holder/... -v
go test ./verifier/... -v
go test ./sdjwt/... -v
go test ./sdjwtvc/... -v
go test ./statuslist/... -v
go test ./signer/... -v
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
