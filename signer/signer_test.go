package signer

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDefaultSigner(t *testing.T) {
	s, err := NewDefaultSigner()
	if err != nil {
		t.Fatalf("failed to create default signer: %v", err)
	}

	t.Run("Algorithm returns correct algorithm", func(t *testing.T) {
		if got := s.Algorithm(); got != "ES256" {
			t.Errorf("Algorithm() = %q, want %q", got, "ES256")
		}
	})

	t.Run("Sign produces valid signature", func(t *testing.T) {
		signingInput := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
		sig, err := s.Sign(signingInput)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if len(sig) == 0 {
			t.Error("Sign() returned empty signature")
		}

		// Verify the signature using the standard jwt library
		err = jwt.SigningMethodES256.Verify(signingInput, sig, s.PublicKey())
		if err != nil {
			t.Errorf("signature verification failed: %v", err)
		}
	})
}

func TestSigningMethod(t *testing.T) {
	s, err := NewDefaultSigner()
	if err != nil {
		t.Fatalf("failed to create default signer: %v", err)
	}
	method := NewSigningMethod(s)

	t.Run("Alg returns correct algorithm", func(t *testing.T) {
		if got := method.Alg(); got != "ES256" {
			t.Errorf("Alg() = %q, want %q", got, "ES256")
		}
	})

	t.Run("Sign ignores key parameter", func(t *testing.T) {
		signingInput := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
		// The key parameter should be ignored since the Signer manages its own key
		sig, err := method.Sign(signingInput, nil)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if len(sig) == 0 {
			t.Error("Sign() returned empty signature")
		}

		// Verify the signature
		err = jwt.SigningMethodES256.Verify(signingInput, sig, s.PublicKey())
		if err != nil {
			t.Errorf("signature verification failed: %v", err)
		}
	})

	t.Run("Verify returns error", func(t *testing.T) {
		// SigningMethod's Verify is not supported
		err := method.Verify("test", []byte("sig"), nil)
		if err == nil {
			t.Error("Verify() should return an error")
		}
	})
}

// MockSigner is a test signer that records calls
type MockSigner struct {
	SignCalls    []string
	SignResponse []byte
	SignError    error
	Alg          string
	PublicKeyVal crypto.PublicKey
}

func (m *MockSigner) Sign(signingInput string) ([]byte, error) {
	m.SignCalls = append(m.SignCalls, signingInput)
	return m.SignResponse, m.SignError
}

func (m *MockSigner) Algorithm() string {
	return m.Alg
}

func (m *MockSigner) PublicKey() crypto.PublicKey {
	return m.PublicKeyVal
}

func (m *MockSigner) Certificate() *x509.Certificate {
	return nil
}

func (m *MockSigner) CertificateChain() []*x509.Certificate {
	return nil
}

func TestSigningMethodWithMockSigner(t *testing.T) {
	mock := &MockSigner{
		Alg:          "custom-alg",
		SignResponse: []byte("test-signature"),
	}

	method := NewSigningMethod(mock)

	t.Run("Alg delegates to signer", func(t *testing.T) {
		if got := method.Alg(); got != "custom-alg" {
			t.Errorf("Alg() = %q, want %q", got, "custom-alg")
		}
	})

	t.Run("Sign delegates to signer", func(t *testing.T) {
		signingInput := "test-input"
		sig, err := method.Sign(signingInput, nil)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		if string(sig) != "test-signature" {
			t.Errorf("Sign() = %q, want %q", sig, "test-signature")
		}

		if len(mock.SignCalls) != 1 || mock.SignCalls[0] != signingInput {
			t.Errorf("Sign() did not call signer with correct input")
		}
	})
}

func TestSigningMethodIntegrationWithJWT(t *testing.T) {
	s, err := NewDefaultSigner()
	if err != nil {
		t.Fatalf("failed to create default signer: %v", err)
	}
	method := NewSigningMethod(s)

	// Create a JWT using our SigningMethod
	claims := jwt.MapClaims{
		"sub": "1234567890",
		"iss": "test-issuer",
	}

	token := jwt.NewWithClaims(method, claims)
	signedJWT, err := token.SignedString(nil) // key is nil, managed by signer
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	// Parse and verify the JWT using standard method
	parsedToken, err := jwt.Parse(signedJWT, func(token *jwt.Token) (interface{}, error) {
		return s.PublicKey(), nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}

	if !parsedToken.Valid {
		t.Error("parsed token is not valid")
	}

	parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to get claims from parsed token")
	}

	if parsedClaims["sub"] != "1234567890" {
		t.Errorf("sub claim = %v, want %v", parsedClaims["sub"], "1234567890")
	}
	if parsedClaims["iss"] != "test-issuer" {
		t.Errorf("iss claim = %v, want %v", parsedClaims["iss"], "test-issuer")
	}
}
