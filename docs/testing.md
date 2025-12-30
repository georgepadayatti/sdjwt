# Testing

This document describes the test coverage and how to run tests for the SD-JWT library.

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

# Run a specific test
go test ./issuer/... -run TestFlatDisclosure -v
```

## Test Coverage

### Issuer Tests (`issuer/rfc9901_issuer_test.go`)

Tests for SD-JWT issuance covering all disclosure patterns:

| Test | Description |
|------|-------------|
| `TestFlatDisclosure` | Disclose entire nested object as single unit |
| `TestStructuredDisclosure` | Disclose individual sub-claims within nested object |
| `TestRecursiveDisclosure` | Both parent object AND sub-claims are selectively disclosable |
| `TestArrayElementDisclosure` | Disclose individual array elements separately |
| `TestFullArrayDisclosure` | Disclose entire array as single unit |
| `TestDecoyDigests` | Add decoy digests to hide true number of claims |
| `TestNestedDecoyDigests` | Add decoys at nested levels |
| `TestArrayDecoyDigests` | Add decoys in array elements |
| `TestComplexNestedStructure` | Handle deeply nested structures (verified_claims) |
| `TestDeepNesting` | Test arbitrary nesting depth |
| `TestMixedArrayContent` | Some array elements SD, others always visible |
| `TestHashAlgorithms` | Test sha-256, sha-384, sha-512 |
| `TestJWTTypeHeader` | Verify typ header in JWT |
| `TestHolderBinding` | Test holder public key binding (cnf claim) |
| `TestNoDisclosures` | Issue SD-JWT with no selective disclosure |
| `TestNilFrame` | Issue with nil disclosure frame |
| `TestSerialization` | Compact, FlattenJSON, GeneralJSON formats |
| `TestAllClaimTypesSD` | Test all JSON types (string, number, bool, null, object, array) |

### Holder Tests (`holder/holder_test.go`)

Tests for holder presentation creation:

| Test | Description |
|------|-------------|
| `TestPresentWithFrameFlatDisclosure` | Present flat disclosure claims |
| `TestPresentWithFrameStructuredDisclosure` | Present structured nested claims |
| `TestPresentWithFrameRecursiveDisclosure` | Present recursive disclosure claims |
| `TestPresentWithFrameArrayElements` | Present individual array elements |
| `TestPresentWithFrameNoKB` | Create presentation without key binding |
| `TestPresentWithNilFrame` | Present all disclosures with nil frame |
| `TestGetPresentableKeys` | Get list of presentable claim keys |
| `TestGetProcessedPayload` | Get fully processed payload with disclosures applied |
| `TestParseAndCreateHolder` | Parse serialized SD-JWT and create holder |
| `TestKeyBindingJWTCreation` | Verify KB-JWT contains sd_hash, aud, nonce, iat |
| `TestPresentationSerialization` | Serialize presentation to compact format |
| `TestComplexNestedPresentation` | Present from complex nested structure |
| `TestGetHolderPublicKey` | Extract holder public key from cnf claim |
| `TestVerifyIssuerSignature` | Verify issuer signature on SD-JWT |

### Verifier Tests (`verifier/verifier_test.go`)

Tests for presentation verification:

| Test | Description |
|------|-------------|
| `TestVerifyFlatDisclosure` | Verify flat disclosure presentation |
| `TestVerifyStructuredDisclosure` | Verify structured disclosure presentation |
| `TestVerifyArrayElementDisclosure` | Verify array element disclosure presentation |
| `TestVerifyWithoutKeyBinding` | Verify presentation without KB-JWT |
| `TestVerifyMissingRequiredClaims` | Fail when required claims are missing |
| `TestVerifyInvalidIssuerSignature` | Fail with invalid issuer signature |
| `TestVerifyInvalidKBJWTNonce` | Fail with wrong nonce in KB-JWT |
| `TestVerifyInvalidKBJWTAudience` | Fail with wrong audience in KB-JWT |
| `TestVerifyKBJWTMaxAge` | Fail when KB-JWT exceeds max age |
| `TestVerifyMissingKeyBindingWhenRequired` | Fail when KB required but missing |
| `TestVerifyRequiredClaimInPayload` | Pass when required claim is in JWT payload |
| `TestVerifyTrustedIssuers` | Verify against list of trusted issuers |
| `TestVerifyHashAlgorithms` | Verify with sha-256, sha-384, sha-512 |
| `TestVerifyProcessedPayload` | Verify processed payload in result |
| `TestVerifySDJWTString` | Verify using convenience string method |

### Signer Tests (`signer/signer_test.go`)

Tests for custom signer interface:

| Test | Description |
|------|-------------|
| `TestDefaultSigner` | Test DefaultSigner with local key |
| `TestSigningMethodAdapter` | Test SigningMethod adapter for jwt-go |
| `TestCustomSignerIntegration` | Test custom signer with issuer |
| `TestAlgorithmSupport` | Test all supported algorithms |

### Core Package Tests

- **sdjwt/** - Disclosure creation/parsing, hash functions, frame operations, serialization
- **sdjwtvc/** - VC issuance, validation, metadata, claim paths, ETSI EAA
- **statuslist/** - Status list creation, encoding, token generation

## Running Examples

```bash
go run ./examples
```

The examples demonstrate:
1. Basic SD-JWT flow (issue, present, verify)
2. Nested claims with selective disclosure
3. Array element disclosure
4. Serialization formats (compact, flatten JSON, general JSON)
5. SD-JWT VC (Verifiable Credentials)
6. Status list for credential revocation
7. VCT metadata structures
8. Custom signer interface (HSM/KMS integration)
9. ETSI EAA (Electronic Attestation of Attributes)
