package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
)

// publicKeyToJWK converts a supported public key to JWK format.
func publicKeyToJWK(pub crypto.PublicKey) []byte {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	curveName := ""
	switch ecdsaPub.Curve {
	case elliptic.P256():
		curveName = "P-256"
	case elliptic.P384():
		curveName = "P-384"
	case elliptic.P521():
		curveName = "P-521"
	}

	byteSize := (ecdsaPub.Curve.Params().BitSize + 7) / 8
	xBytes := ecdsaPub.X.Bytes()
	yBytes := ecdsaPub.Y.Bytes()

	xPadded := make([]byte, byteSize)
	yPadded := make([]byte, byteSize)
	copy(xPadded[byteSize-len(xBytes):], xBytes)
	copy(yPadded[byteSize-len(yBytes):], yBytes)

	jwk := map[string]string{
		"kty": "EC",
		"crv": curveName,
		"x":   base64URLEncode(xPadded),
		"y":   base64URLEncode(yPadded),
	}

	data, _ := json.Marshal(jwk)
	return data
}

func base64URLEncode(data []byte) string {
	encoded := make([]byte, base64URLEncodedLen(len(data)))
	base64URLEncodeBytes(encoded, data)
	return string(encoded)
}

const base64URLChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func base64URLEncodedLen(n int) int {
	return (n*8 + 5) / 6
}

func base64URLEncodeBytes(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = base64URLChars[val>>18&0x3F]
		dst[di+1] = base64URLChars[val>>12&0x3F]
		dst[di+2] = base64URLChars[val>>6&0x3F]
		dst[di+3] = base64URLChars[val&0x3F]
		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return
	}

	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = base64URLChars[val>>18&0x3F]
	dst[di+1] = base64URLChars[val>>12&0x3F]
	if remain == 2 {
		dst[di+2] = base64URLChars[val>>6&0x3F]
	}
}
