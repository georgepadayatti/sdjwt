# Custom Signer Interface

The `signer` package provides an interface for custom signing implementations, enabling integration with HSMs, cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault), and other external signing services.

## The Signer Interface

```go
// Signer defines an interface for JWT signing operations.
// Implement this interface to use external signing services like HSMs or cloud KMS.
type Signer interface {
    // Sign signs the JWT content and returns the signature.
    // The signingInput is the JWT content to sign: base64url(header) + "." + base64url(payload)
    // Returns the raw signature bytes (which will be base64url encoded by the caller).
    Sign(signingInput string) ([]byte, error)

    // Algorithm returns the JWT "alg" header value (e.g., "ES256", "RS256", "EdDSA").
    Algorithm() string

    // PublicKey returns the public key corresponding to the signing key.
    PublicKey() crypto.PublicKey

    // Certificate returns the signing certificate if available.
    Certificate() *x509.Certificate

    // CertificateChain returns the full certificate chain if available.
    CertificateChain() []*x509.Certificate
}
```

## Using Custom Signers

### With Issuer

```go
import "github.com/georgepadayatti/sdjwt/issuer"

// Create issuer with custom signer
iss := issuer.NewIssuer(customSigner)

// Issue SD-JWT as normal
sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
```

### With Holder (Key Binding JWT)

```go
import "github.com/georgepadayatti/sdjwt/holder"

// Create KB-JWT using custom signer
kbJWT, _ := holder.CreateKeyBindingJWT(sdj, holderSigner, kbOptions)
```

### With VC Issuer

```go
import "github.com/georgepadayatti/sdjwt/sdjwtvc"

// Create VC issuer with custom signer
vcIssuer := sdjwtvc.NewVCIssuerWithSigner("https://issuer.example.com", customSigner, "sha-256")

// Or via IssuerConfig
vcIssuer := sdjwtvc.NewVCIssuer(sdjwtvc.IssuerConfig{
    IssuerID: "https://issuer.example.com",
    Signer:   customSigner,
})
```

## DefaultSigner (Local Keys)

For local key signing, use the built-in `DefaultSigner`:

```go
import "github.com/georgepadayatti/sdjwt/signer"

// Create a default signer (self-signed X.509)
s, _ := signer.NewDefaultSigner()

// Use with issuer
iss := issuer.NewIssuer(s)
```

## Example: AWS KMS Signer

```go
import (
    "context"
    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KMSSigner struct {
    kmsClient *kms.Client
    keyID     string
    algorithm string
    publicKey crypto.PublicKey
}

func NewKMSSigner(client *kms.Client, keyID string, publicKey crypto.PublicKey) *KMSSigner {
    return &KMSSigner{
        kmsClient: client,
        keyID:     keyID,
        algorithm: "ES256",
        publicKey: publicKey,
    }
}

func (s *KMSSigner) Sign(signingInput string) ([]byte, error) {
    resp, err := s.kmsClient.Sign(context.Background(), &kms.SignInput{
        KeyId:            aws.String(s.keyID),
        Message:          []byte(signingInput),
        MessageType:      types.MessageTypeRaw,
        SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
    })
    if err != nil {
        return nil, err
    }
    return resp.Signature, nil
}

func (s *KMSSigner) Algorithm() string {
    return s.algorithm
}

func (s *KMSSigner) PublicKey() crypto.PublicKey {
    return s.publicKey
}

func (s *KMSSigner) Certificate() *x509.Certificate {
    return nil
}

func (s *KMSSigner) CertificateChain() []*x509.Certificate {
    return nil
}

// Usage
kmsSigner := NewKMSSigner(kmsClient, "alias/my-signing-key", kmsPublicKey)
iss := issuer.NewIssuer(kmsSigner)
sdJWT, _ := iss.IssueWithFrame(claims, frame, nil)
```

## Example: Google Cloud KMS Signer

```go
import (
    "context"
    "hash/crc32"
    kms "cloud.google.com/go/kms/apiv1"
    kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type GCPKMSSigner struct {
    client  *kms.KeyManagementClient
    keyName string
    algorithm string
    publicKey crypto.PublicKey
}

func NewGCPKMSSigner(client *kms.KeyManagementClient, keyName string, publicKey crypto.PublicKey) *GCPKMSSigner {
    return &GCPKMSSigner{
        client:    client,
        keyName:   keyName,
        algorithm: "ES256",
        publicKey: publicKey,
    }
}

func (s *GCPKMSSigner) Sign(signingInput string) ([]byte, error) {
    digest := sha256.Sum256([]byte(signingInput))

    req := &kmspb.AsymmetricSignRequest{
        Name: s.keyName,
        Digest: &kmspb.Digest{
            Digest: &kmspb.Digest_Sha256{
                Sha256: digest[:],
            },
        },
    }

    resp, err := s.client.AsymmetricSign(context.Background(), req)
    if err != nil {
        return nil, err
    }
    return resp.Signature, nil
}

func (s *GCPKMSSigner) Algorithm() string {
    return s.algorithm
}

func (s *GCPKMSSigner) PublicKey() crypto.PublicKey {
    return s.publicKey
}

func (s *GCPKMSSigner) Certificate() *x509.Certificate {
    return nil
}

func (s *GCPKMSSigner) CertificateChain() []*x509.Certificate {
    return nil
}
```

## Example: Azure Key Vault Signer

```go
import (
    "context"
    "github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

type AzureKVSigner struct {
    client    *azkeys.Client
    keyName   string
    algorithm string
    publicKey crypto.PublicKey
}

func NewAzureKVSigner(client *azkeys.Client, keyName string, publicKey crypto.PublicKey) *AzureKVSigner {
    return &AzureKVSigner{
        client:    client,
        keyName:   keyName,
        algorithm: "ES256",
        publicKey: publicKey,
    }
}

func (s *AzureKVSigner) Sign(signingInput string) ([]byte, error) {
    digest := sha256.Sum256([]byte(signingInput))

    resp, err := s.client.Sign(context.Background(), s.keyName, "", azkeys.SignParameters{
        Algorithm: to.Ptr(azkeys.JSONWebKeySignatureAlgorithmES256),
        Value:     digest[:],
    }, nil)
    if err != nil {
        return nil, err
    }
    return resp.Result, nil
}

func (s *AzureKVSigner) Algorithm() string {
    return s.algorithm
}

func (s *AzureKVSigner) PublicKey() crypto.PublicKey {
    return s.publicKey
}

func (s *AzureKVSigner) Certificate() *x509.Certificate {
    return nil
}

func (s *AzureKVSigner) CertificateChain() []*x509.Certificate {
    return nil
}

func (s *AzureKVSigner) Algorithm() string {
    return s.algorithm
}
```

## Example: PKCS#11 HSM Signer

```go
import (
    "github.com/miekg/pkcs11"
)

type PKCS11Signer struct {
    ctx       *pkcs11.Ctx
    session   pkcs11.SessionHandle
    keyHandle pkcs11.ObjectHandle
    algorithm string
}

func (s *PKCS11Signer) Sign(signingInput string) ([]byte, error) {
    mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

    err := s.ctx.SignInit(s.session, mechanism, s.keyHandle)
    if err != nil {
        return nil, err
    }

    digest := sha256.Sum256([]byte(signingInput))
    signature, err := s.ctx.Sign(s.session, digest[:])
    if err != nil {
        return nil, err
    }

    return signature, nil
}

func (s *PKCS11Signer) Algorithm() string {
    return s.algorithm
}
```

## Supported Algorithms

The signer interface supports all standard JWT signing algorithms:

- **ECDSA**: ES256, ES384, ES512
- **RSA**: RS256, RS384, RS512
- **RSA-PSS**: PS256, PS384, PS512
- **EdDSA**: EdDSA

Ensure your custom signer returns the correct algorithm string matching the key type.
