package sdjwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestConfirmationPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}

	key, alg, err := claims.ConfirmationPublicKey()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	got, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", key)
	}

	if !bytes.Equal(got, pub) {
		t.Fatal("returned Ed25519 key does not match")
	}

	if alg != "EdDSA" {
		t.Fatalf("expected EdDSA, got %q", alg)
	}
}

func TestConfirmationPublicKey_Ed25519ExplicitAlg(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Alg: "EdDSA",
	}

	_, alg, err := claims.ConfirmationPublicKey()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if alg != "EdDSA" {
		t.Fatalf("expected EdDSA, got %q", alg)
	}
}

func TestConfirmationPublicKey_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "EC",
		Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(
			priv.PublicKey.X.FillBytes(make([]byte, 32)),
		),
		Y: base64.RawURLEncoding.EncodeToString(
			priv.PublicKey.Y.FillBytes(make([]byte, 32)),
		),
	}

	key, alg, err := claims.ConfirmationPublicKey()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	got, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	if got.X.Cmp(priv.PublicKey.X) != 0 {
		t.Fatal("X coordinate does not match")
	}

	if got.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("Y coordinate does not match")
	}

	if alg != "ES256" {
		t.Fatalf("expected ES256, got %q", alg)
	}
}

func TestConfirmationPublicKey_ES256ExplicitAlg(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "EC",
		Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(
			priv.PublicKey.X.FillBytes(make([]byte, 32)),
		),
		Y: base64.RawURLEncoding.EncodeToString(
			priv.PublicKey.Y.FillBytes(make([]byte, 32)),
		),
		Alg: "ES256",
	}

	_, alg, err := claims.ConfirmationPublicKey()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if alg != "ES256" {
		t.Fatalf("expected ES256, got %q", alg)
	}
}

func TestConfirmationPublicKey_NilClaims(t *testing.T) {
	var claims *IssuerClaims

	_, _, err := claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_UnsupportedKeyType(t *testing.T) {
	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "RSA",
	}

	_, _, err := claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_UnsupportedOKPCurve(t *testing.T) {
	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "X25519",
		X:   "abc",
	}

	_, _, err := claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_InvalidEd25519X(t *testing.T) {
	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   "%%%not-base64%%%",
	}

	_, _, err := claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_InvalidEd25519Length(t *testing.T) {
	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(
			make([]byte, ed25519.PublicKeySize-1),
		),
	}

	_, _, err := claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_MissingECY(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "EC",
		Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(
			priv.PublicKey.X.FillBytes(make([]byte, 32)),
		),
	}

	_, _, err = claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_InvalidECPoint(t *testing.T) {
	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "EC",
		Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(
			make([]byte, 32),
		),
		Y: base64.RawURLEncoding.EncodeToString(
			make([]byte, 32),
		),
	}

	_, _, err := claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}

func TestConfirmationPublicKey_InfersEdDSAWhenAlgMissing(t *testing.T) {
	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(
			make([]byte, ed25519.PublicKeySize),
		),
		Alg: "",
	}

	// This one actually WILL infer EdDSA, so use a valid-but
	// unsupported combination if you later add more JWK types.
	_, _, err := claims.ConfirmationPublicKey()

	if err != nil {
		t.Fatalf("expected EdDSA inference, got %v", err)
	}
}

func TestConfirmationPublicKey_RejectsMismatchedAlgorithm(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &IssuerClaims{}
	claims.CNF.JWK = JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Alg: "ES256",
	}

	_, _, err = claims.ConfirmationPublicKey()

	if !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("expected ErrInvalidJWK, got %v", err)
	}
}
