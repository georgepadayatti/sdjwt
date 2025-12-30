package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// buildECDSAKey constructs an ECDSA public key from curve name and coordinates.
func buildECDSAKey(curveName string, x, y []byte) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	switch curveName {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveName)
	}

	xBig := new(big.Int).SetBytes(x)
	yBig := new(big.Int).SetBytes(y)

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     xBig,
		Y:     yBig,
	}

	// Validate the point is on the curve
	if !curve.IsOnCurve(xBig, yBig) {
		return nil, fmt.Errorf("point is not on curve")
	}

	return pubKey, nil
}

// buildRSAKey constructs an RSA public key from modulus and exponent.
func buildRSAKey(n, e []byte) (crypto.PublicKey, error) {
	nBig := new(big.Int).SetBytes(n)

	// Calculate exponent from bytes
	eBig := new(big.Int).SetBytes(e)
	if !eBig.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large")
	}
	eInt := int(eBig.Int64())

	pubKey := &rsa.PublicKey{
		N: nBig,
		E: eInt,
	}

	return pubKey, nil
}

// buildEd25519Key constructs an Ed25519 public key from the x coordinate.
func buildEd25519Key(x []byte) (crypto.PublicKey, error) {
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: expected %d, got %d", ed25519.PublicKeySize, len(x))
	}

	return ed25519.PublicKey(x), nil
}
