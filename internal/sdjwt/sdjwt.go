package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
)

var (
	ErrInvalidPresentation = errors.New("invalid SD-JWT presentation")
	ErrMissingKeyBinding   = errors.New("missing key binding JWT")
	ErrInvalidKeyBinding   = errors.New("invalid key binding JWT")
	ErrInvalidSDHash       = errors.New("invalid sd_hash")
	ErrInvalidIssuerJWT    = errors.New("invalid issuer JWT")
	ErrInvalidJWK          = errors.New("invalid JWK")

	ErrNonceMismatch    = errors.New("nonce mismatch")
	ErrAudienceMismatch = errors.New("audience mismatch")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenNotYetValid = errors.New("token issued in the future")
	ErrMissingIssuedAt  = errors.New("missing iat")
	ErrMissingSDHash    = errors.New("missing sd_hash")
	ErrMissingNonce     = errors.New("missing nonce")
	ErrInvalidTokenType = errors.New("invalid JWT type")
)

type Presentation struct {
	IssuerJWT   string
	Disclosures []string
	KeyBinding  string
}

type KeyBindingClaims struct {
	SDHash string `json:"sd_hash"`
	Nonce  string `json:"nonce"`

	jwt.RegisteredClaims
}

type IssuerClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	CNF struct {
		JWK JWK `json:"jwk"`
	} `json:"cnf"`

	IsPrivateEmail bool `json:"is_private_email"`

	jwt.RegisteredClaims
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
}

func Parse(raw string) (*Presentation, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf(
			"%w: token is empty",
			ErrInvalidPresentation,
		)
	}

	parts := strings.Split(raw, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf(
			"%w: expected issuer JWT and key binding JWT",
			ErrInvalidPresentation,
		)
	}

	issuerJWT := parts[0]
	keyBinding := parts[len(parts)-1]

	if issuerJWT == "" {
		return nil, fmt.Errorf(
			"%w: missing issuer JWT",
			ErrInvalidPresentation,
		)
	}

	if keyBinding == "" {
		return nil, fmt.Errorf(
			"%w: %w",
			ErrInvalidPresentation,
			ErrMissingKeyBinding,
		)
	}

	disclosures := make([]string, 0, len(parts)-2)

	for _, disclosure := range parts[1 : len(parts)-1] {
		if disclosure == "" {
			continue
		}

		disclosures = append(disclosures, disclosure)
	}

	return &Presentation{
		IssuerJWT:   issuerJWT,
		Disclosures: disclosures,
		KeyBinding:  keyBinding,
	}, nil
}

func ParseIssuerClaimsUnverified(raw string) (*IssuerClaims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf(
			"%w: issuer JWT is empty",
			ErrInvalidIssuerJWT,
		)
	}

	claims := &IssuerClaims{}

	parser := jwt.NewParser()

	_, _, err := parser.ParseUnverified(raw, claims)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to parse claims: %v",
			ErrInvalidIssuerJWT,
			err,
		)
	}

	if claims.Issuer == "" {
		return nil, fmt.Errorf(
			"%w: missing iss claim",
			ErrInvalidIssuerJWT,
		)
	}

	return claims, nil
}

func VerifyIssuerJWT(
	p *Presentation,
	config *evp_domain.IssuerConfiguration,
	keyfunc jwt.Keyfunc,
	maxAge time.Duration,
) (*IssuerClaims, error) {
	if p == nil {
		return nil, ErrInvalidPresentation
	}

	if config == nil {
		return nil, fmt.Errorf(
			"%w: issuer configuration is required",
			ErrInvalidIssuerJWT,
		)
	}

	if keyfunc == nil {
		return nil, fmt.Errorf(
			"%w: keyfunc is required",
			ErrInvalidIssuerJWT,
		)
	}

	claims := &IssuerClaims{}

	token, err := jwt.ParseWithClaims(
		p.IssuerJWT,
		claims,
		keyfunc,
		jwt.WithValidMethods(config.SigningAlgorithmsSupported),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w",
			ErrInvalidIssuerJWT,
			err,
		)
	}

	if token.Header["typ"] != "evt+jwt" {
		return nil, fmt.Errorf(
			"%w: invalid token type: %v",
			ErrInvalidIssuerJWT,
			token.Header["typ"],
		)
	}

	// While spec says KID is required, Chrome does not include it in the token header
	// as of 151 & therefor it is not required currently.

	if !token.Valid {
		return nil, ErrInvalidIssuerJWT
	}

	if claims.IssuedAt == nil {
		return nil, fmt.Errorf(
			"%w: %w",
			ErrInvalidIssuerJWT,
			ErrMissingIssuedAt,
		)
	}

	if maxAge > 0 &&
		time.Since(claims.IssuedAt.Time) > maxAge {
		return nil, fmt.Errorf(
			"%w: %w",
			ErrInvalidIssuerJWT,
			ErrTokenExpired,
		)
	}

	return claims, nil
}

func (c *IssuerClaims) ConfirmationPublicKey() (crypto.PublicKey, string, error) {
	if c == nil {
		return nil, "", ErrInvalidJWK
	}

	key, err := c.CNF.JWK.PublicKey()
	if err != nil {
		return nil, "", err
	}

	jwk := c.CNF.JWK

	expectedAlg := ""

	switch jwk.Kty {
	case "OKP":
		if jwk.Crv == "Ed25519" {
			expectedAlg = "EdDSA"
		}

	case "EC":
		if jwk.Crv == "P-256" {
			expectedAlg = "ES256"
		}
	}

	if expectedAlg == "" {
		return nil, "", fmt.Errorf(
			"%w: unable to determine signing algorithm for kty=%q crv=%q",
			ErrInvalidJWK,
			jwk.Kty,
			jwk.Crv,
		)
	}

	if jwk.Alg != "" && jwk.Alg != expectedAlg {
		return nil, "", fmt.Errorf(
			"%w: alg %q is incompatible with kty=%q crv=%q",
			ErrInvalidJWK,
			jwk.Alg,
			jwk.Kty,
			jwk.Crv,
		)
	}

	return key, expectedAlg, nil
}

func (j JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "OKP":
		return j.okpPublicKey()

	case "EC":
		return j.ecPublicKey()

	default:
		return nil, fmt.Errorf(
			"%w: unsupported kty %q",
			ErrInvalidJWK,
			j.Kty,
		)
	}
}

func (j JWK) okpPublicKey() (crypto.PublicKey, error) {
	if j.Crv != "Ed25519" {
		return nil, fmt.Errorf(
			"%w: unsupported OKP curve %q",
			ErrInvalidJWK,
			j.Crv,
		)
	}

	if j.X == "" {
		return nil, fmt.Errorf(
			"%w: missing x coordinate",
			ErrInvalidJWK,
		)
	}

	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: invalid x coordinate: %v",
			ErrInvalidJWK,
			err,
		)
	}

	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"%w: invalid Ed25519 key length %d",
			ErrInvalidJWK,
			len(x),
		)
	}

	return ed25519.PublicKey(x), nil
}

func (j JWK) ecPublicKey() (crypto.PublicKey, error) {
	if j.Crv != "P-256" {
		return nil, fmt.Errorf(
			"%w: unsupported EC curve %q",
			ErrInvalidJWK,
			j.Crv,
		)
	}

	if j.X == "" || j.Y == "" {
		return nil, fmt.Errorf(
			"%w: EC key requires x and y coordinates",
			ErrInvalidJWK,
		)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: invalid x coordinate: %v",
			ErrInvalidJWK,
			err,
		)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: invalid y coordinate: %v",
			ErrInvalidJWK,
			err,
		)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	curve := elliptic.P256()

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf(
			"%w: EC point is not on P-256",
			ErrInvalidJWK,
		)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func VerifyKeyBinding(
	p *Presentation,
	key crypto.PublicKey,
	alg string,
	nonce string,
	audience string,
	replayWindow time.Duration,
) error {
	if p == nil {
		return ErrInvalidPresentation
	}

	if p.KeyBinding == "" {
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidKeyBinding,
			ErrMissingKeyBinding,
		)
	}

	if key == nil {
		return fmt.Errorf(
			"%w: confirmation public key is required",
			ErrInvalidKeyBinding,
		)
	}

	if alg == "" {
		return fmt.Errorf(
			"%w: signing algorithm is required",
			ErrInvalidKeyBinding,
		)
	}

	if nonce == "" {
		return fmt.Errorf(
			"%w: expected nonce is required",
			ErrInvalidKeyBinding,
		)
	}

	if audience == "" {
		return fmt.Errorf(
			"%w: expected audience is required",
			ErrInvalidKeyBinding,
		)
	}

	claims := &KeyBindingClaims{}

	token, err := jwt.ParseWithClaims(
		p.KeyBinding,
		claims,
		func(token *jwt.Token) (any, error) {
			typ, _ := token.Header["typ"].(string)
			if typ != "kb+jwt" {
				return nil, fmt.Errorf(
					"%w: %w: got %q",
					ErrInvalidKeyBinding,
					ErrInvalidTokenType,
					typ,
				)
			}

			return key, nil
		},
		jwt.WithValidMethods([]string{alg}),
		jwt.WithAudience(audience),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		// jwt/v5 performs audience validation itself, so classify it.
		if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return fmt.Errorf(
				"%w: %w: %v",
				ErrInvalidKeyBinding,
				ErrAudienceMismatch,
				err,
			)
		}

		if errors.Is(err, jwt.ErrTokenUsedBeforeIssued) {
			return fmt.Errorf(
				"%w: %w",
				ErrInvalidKeyBinding,
				ErrTokenNotYetValid,
			)
		}

		if errors.Is(err, ErrInvalidTokenType) {
			return fmt.Errorf(
				"%w: %w",
				ErrInvalidKeyBinding,
				ErrInvalidTokenType,
			)
		}

		return fmt.Errorf(
			"%w: %v",
			ErrInvalidKeyBinding,
			err,
		)
	}

	if !token.Valid {
		return ErrInvalidKeyBinding
	}

	if claims.Nonce == "" {
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidKeyBinding,
			ErrMissingNonce,
		)
	}

	if claims.Nonce != nonce {
		return fmt.Errorf(
			"%w: %w: token=%q expected=%q",
			ErrInvalidKeyBinding,
			ErrNonceMismatch,
			claims.Nonce,
			nonce,
		)
	}

	if claims.SDHash == "" {
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidKeyBinding,
			ErrMissingSDHash,
		)
	}

	expectedHash := calculateSDHash(p)

	if claims.SDHash != expectedHash {
		return fmt.Errorf(
			"%w: expected=%q got=%q",
			ErrInvalidSDHash,
			expectedHash,
			claims.SDHash,
		)
	}

	if claims.IssuedAt == nil {
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidKeyBinding,
			ErrMissingIssuedAt,
		)
	}

	now := time.Now()

	if replayWindow > 0 &&
		now.Sub(claims.IssuedAt.Time) > replayWindow {
		return fmt.Errorf(
			"%w: %w: issued_at=%s max_age=%s",
			ErrInvalidKeyBinding,
			ErrTokenExpired,
			claims.IssuedAt.Time.UTC().Format(time.RFC3339),
			replayWindow,
		)
	}

	return nil
}

func calculateSDHash(p *Presentation) string {
	var b strings.Builder

	b.WriteString(p.IssuerJWT)
	b.WriteByte('~')

	for _, disclosure := range p.Disclosures {
		b.WriteString(disclosure)
		b.WriteByte('~')
	}

	sum := sha256.Sum256([]byte(b.String()))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
