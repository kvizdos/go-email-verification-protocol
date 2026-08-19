package sdjwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
)

const testEVTMaxAge = 5 * time.Minute

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{
			name:    "empty",
			raw:     "",
			wantErr: ErrInvalidPresentation,
		},
		{
			name:    "issuer only",
			raw:     "abc.def.sig",
			wantErr: ErrInvalidPresentation,
		},
		{
			name:    "missing key binding",
			raw:     "abc.def.sig~",
			wantErr: ErrMissingKeyBinding,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.raw)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestVerifyKeyBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const (
		nonce    = "expected-nonce"
		audience = "https://example.com"
	)

	basePresentation := &Presentation{
		IssuerJWT:   "issuer.jwt.signature",
		Disclosures: nil,
	}

	validSDHash := calculateSDHash(basePresentation)

	tests := []struct {
		name         string
		key          ed25519.PublicKey
		signingKey   ed25519.PrivateKey
		alg          string
		nonce        string
		audience     string
		replayWindow time.Duration

		claims KeyBindingClaims
		typ    string

		wantErr error
	}{
		{
			name:         "valid",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
		},
		{
			name:         "nonce mismatch",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  "wrong-nonce",
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			wantErr: ErrNonceMismatch,
		},
		{
			name:         "audience mismatch",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{"https://wrong.example.com"},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			wantErr: ErrAudienceMismatch,
		},
		{
			name:         "invalid sd hash",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: "not-the-correct-hash",
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			wantErr: ErrInvalidSDHash,
		},
		{
			name:         "missing nonce",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			wantErr: ErrMissingNonce,
		},
		{
			name:         "missing sd hash",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				Nonce: nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			wantErr: ErrMissingSDHash,
		},
		{
			name:         "missing issued at",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
				},
			},
			wantErr: ErrMissingIssuedAt,
		},
		{
			name:         "expired",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(
						time.Now().Add(-10 * time.Minute),
					),
				},
			},
			wantErr: ErrTokenExpired,
		},
		{
			name:         "issued in future",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(
						time.Now().Add(20 * time.Minute),
					),
				},
			},
			wantErr: ErrTokenNotYetValid,
		},
		{
			name:         "wrong token type",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 5 * time.Minute,
			typ:          "JWT",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			wantErr: ErrInvalidTokenType,
		},
		{
			name:         "zero replay window disables expiry check",
			key:          pub,
			signingKey:   priv,
			alg:          "EdDSA",
			nonce:        nonce,
			audience:     audience,
			replayWindow: 0,
			typ:          "kb+jwt",
			claims: KeyBindingClaims{
				SDHash: validSDHash,
				Nonce:  nonce,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: jwt.ClaimStrings{audience},
					IssuedAt: jwt.NewNumericDate(
						time.Now().Add(-24 * time.Hour),
					),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := *basePresentation

			token := jwt.NewWithClaims(
				jwt.SigningMethodEdDSA,
				tt.claims,
			)

			token.Header["typ"] = tt.typ

			raw, err := token.SignedString(tt.signingKey)
			if err != nil {
				t.Fatal(err)
			}

			p.KeyBinding = raw

			err = VerifyKeyBinding(
				&p,
				tt.key,
				tt.alg,
				tt.nonce,
				tt.audience,
				tt.replayWindow,
			)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}

				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf(
					"expected error %v, got %v",
					tt.wantErr,
					err,
				)
			}
		})
	}
}

func TestVerifyKeyBinding_InvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: "issuer.jwt.signature",
	}

	claims := KeyBindingClaims{
		SDHash: calculateSDHash(p),
		Nonce:  "nonce",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://example.com"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		claims,
	)

	token.Header["typ"] = "kb+jwt"

	raw, err := token.SignedString(attackerPriv)
	if err != nil {
		t.Fatal(err)
	}

	p.KeyBinding = raw

	err = VerifyKeyBinding(
		p,
		pub,
		"EdDSA",
		"nonce",
		"https://example.com",
		5*time.Minute,
	)

	if !errors.Is(err, ErrInvalidKeyBinding) {
		t.Fatalf(
			"expected ErrInvalidKeyBinding, got %v",
			err,
		)
	}
}

func TestVerifyKeyBinding_WrongAlgorithm(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: "issuer.jwt.signature",
	}

	claims := KeyBindingClaims{
		SDHash: calculateSDHash(p),
		Nonce:  "nonce",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://example.com"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		claims,
	)

	token.Header["typ"] = "kb+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p.KeyBinding = raw

	err = VerifyKeyBinding(
		p,
		pub,
		"ES256", // deliberately wrong
		"nonce",
		"https://example.com",
		5*time.Minute,
	)

	if !errors.Is(err, ErrInvalidKeyBinding) {
		t.Fatalf(
			"expected ErrInvalidKeyBinding, got %v",
			err,
		)
	}
}

func TestVerifyKeyBinding_WithDisclosures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: "issuer.jwt.signature",
		Disclosures: []string{
			"disclosure-one",
			"disclosure-two",
		},
	}

	claims := KeyBindingClaims{
		SDHash: calculateSDHash(p),
		Nonce:  "nonce",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://example.com"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		claims,
	)

	token.Header["typ"] = "kb+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p.KeyBinding = raw

	err = VerifyKeyBinding(
		p,
		pub,
		"EdDSA",
		"nonce",
		"https://example.com",
		5*time.Minute,
	)

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestVerifyKeyBinding_TamperedPresentationBreaksSDHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: "original.issuer.jwt",
	}

	claims := KeyBindingClaims{
		SDHash: calculateSDHash(p),
		Nonce:  "nonce",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://example.com"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "kb+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p.KeyBinding = raw

	// Mutate the presentation after the KB-JWT was created.
	p.IssuerJWT = "tampered.issuer.jwt"

	err = VerifyKeyBinding(
		p,
		pub,
		"EdDSA",
		"nonce",
		"https://example.com",
		5*time.Minute,
	)

	if !errors.Is(err, ErrInvalidSDHash) {
		t.Fatalf("expected ErrInvalidSDHash, got %v", err)
	}
}

func TestVerifyKeyBinding_FutureIssuedAtWithinLeeway(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: "issuer.jwt.signature",
	}

	claims := KeyBindingClaims{
		SDHash: calculateSDHash(p),
		Nonce:  "nonce",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://example.com"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(15 * time.Second)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "kb+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p.KeyBinding = raw

	err = VerifyKeyBinding(
		p,
		pub,
		"EdDSA",
		"nonce",
		"https://example.com",
		5*time.Minute,
	)

	if err != nil {
		t.Fatalf("expected success within leeway, got %v", err)
	}
}

func TestVerifyIssuerJWT_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		return pub, nil
	}

	got, err := VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if got.Email != "user@example.com" {
		t.Fatalf("unexpected email: %q", got.Email)
	}

	if !got.EmailVerified {
		t.Fatal("expected email_verified=true")
	}

	if got.Issuer != "https://issuer.example" {
		t.Fatalf("unexpected issuer: %q", got.Issuer)
	}
}

func TestVerifyIssuerJWT_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"ES256"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	}

	got, err := VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if got.Email != "user@example.com" {
		t.Fatalf("unexpected email: %q", got.Email)
	}
}

func TestVerifyIssuerJWT_InvalidInputs(t *testing.T) {
	validConfig := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	validKeyfunc := func(token *jwt.Token) (any, error) {
		return nil, nil
	}

	tests := []struct {
		name    string
		p       *Presentation
		config  *evp_domain.IssuerConfiguration
		keyfunc jwt.Keyfunc
		wantErr error
	}{
		{
			name:    "nil presentation",
			p:       nil,
			config:  validConfig,
			keyfunc: validKeyfunc,
			wantErr: ErrInvalidPresentation,
		},
		{
			name: "nil config",
			p: &Presentation{
				IssuerJWT: "not-important",
			},
			config:  nil,
			keyfunc: validKeyfunc,
			wantErr: ErrInvalidIssuerJWT,
		},
		{
			name: "nil keyfunc",
			p: &Presentation{
				IssuerJWT: "not-important",
			},
			config:  validConfig,
			keyfunc: nil,
			wantErr: ErrInvalidIssuerJWT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyIssuerJWT(
				tt.p,
				tt.config,
				tt.keyfunc,
				testEVTMaxAge,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf(
					"expected %v, got %v",
					tt.wantErr,
					err,
				)
			}
		})
	}
}

func TestVerifyIssuerJWT_InvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(attackerPriv)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		return pub, nil
	}

	_, err = VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)

	if !errors.Is(err, ErrInvalidIssuerJWT) {
		t.Fatalf(
			"expected ErrInvalidIssuerJWT, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_RejectsUnsupportedAlgorithm(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"ES256"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		t.Fatal("keyfunc should not be called for unsupported algorithm")
		return nil, nil
	}

	_, err = VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)

	if !errors.Is(err, ErrInvalidIssuerJWT) {
		t.Fatalf(
			"expected ErrInvalidIssuerJWT, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_MissingIssuedAt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://issuer.example",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "evt+jwt"
	raw, err := token.SignedString(priv)

	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		return pub, nil
	}

	_, err = VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)

	if !errors.Is(err, ErrMissingIssuedAt) {
		t.Fatalf(
			"expected ErrMissingIssuedAt, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_KeyfuncFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	keyfuncErr := errors.New("JWKS unavailable")

	keyfunc := func(token *jwt.Token) (any, error) {
		return nil, keyfuncErr
	}

	_, err = VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)

	if !errors.Is(err, ErrInvalidIssuerJWT) {
		t.Fatalf(
			"expected ErrInvalidIssuerJWT, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_MalformedJWT(t *testing.T) {
	p := &Presentation{
		IssuerJWT: "definitely-not-a-jwt",
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		t.Fatal("keyfunc should not be reached")
		return nil, nil
	}

	_, err := VerifyIssuerJWT(p, config, keyfunc, testEVTMaxAge)

	if !errors.Is(err, ErrInvalidIssuerJWT) {
		t.Fatalf(
			"expected ErrInvalidIssuerJWT, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_RejectsWrongType(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = "JWT"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyIssuerJWT(
		&Presentation{IssuerJWT: raw},
		&evp_domain.IssuerConfiguration{
			SigningAlgorithmsSupported: []string{"EdDSA"},
		},
		func(token *jwt.Token) (any, error) {
			return pub, nil
		},
		testEVTMaxAge,
	)

	if !errors.Is(err, ErrInvalidIssuerJWT) {
		t.Fatalf("expected ErrInvalidIssuerJWT, got %v", err)
	}
}

func TestVerifyIssuerJWT_Expired(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(
				time.Now().Add(-10 * time.Minute),
			),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		claims,
	)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	p := &Presentation{
		IssuerJWT: raw,
	}

	config := &evp_domain.IssuerConfiguration{
		SigningAlgorithmsSupported: []string{"EdDSA"},
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		return pub, nil
	}

	_, err = VerifyIssuerJWT(
		p,
		config,
		keyfunc,
		5*time.Minute,
	)

	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf(
			"expected ErrTokenExpired, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_WithinMaxAge(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(
				time.Now().Add(-4 * time.Minute),
			),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		claims,
	)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyIssuerJWT(
		&Presentation{
			IssuerJWT: raw,
		},
		&evp_domain.IssuerConfiguration{
			SigningAlgorithmsSupported: []string{
				"EdDSA",
			},
		},
		func(token *jwt.Token) (any, error) {
			return pub, nil
		},
		5*time.Minute,
	)

	if err != nil {
		t.Fatalf(
			"expected token within max age to pass, got %v",
			err,
		)
	}
}

func TestVerifyIssuerJWT_FutureIssuedAt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := IssuerClaims{
		Email:         "user@example.com",
		EmailVerified: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://issuer.example",
			IssuedAt: jwt.NewNumericDate(
				time.Now().Add(20 * time.Minute),
			),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		claims,
	)
	token.Header["typ"] = "evt+jwt"

	raw, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyIssuerJWT(
		&Presentation{
			IssuerJWT: raw,
		},
		&evp_domain.IssuerConfiguration{
			SigningAlgorithmsSupported: []string{
				"EdDSA",
			},
		},
		func(token *jwt.Token) (any, error) {
			return pub, nil
		},
		5*time.Minute,
	)

	if !errors.Is(err, ErrInvalidIssuerJWT) {
		t.Fatalf(
			"expected ErrInvalidIssuerJWT, got %v",
			err,
		)
	}
}
