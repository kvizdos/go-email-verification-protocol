package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
	"github.com/kvizdos/go-email-verification-protocol/internal/sdjwt"
)

const (
	testIssuer   = "https://issuer.example"
	testEmail    = "user@example.com"
	testNonce    = "expected-nonce"
	testAudience = "https://example.com"
)

type verifyFixture struct {
	token string
	opts  evp_domain.VerifyOptions

	issuerPublic  ed25519.PublicKey
	issuerPrivate ed25519.PrivateKey

	browserPublic  ed25519.PublicKey
	browserPrivate ed25519.PrivateKey

	config *evp_domain.IssuerConfiguration
}

type fixtureOptions struct {
	email         string
	emailVerified bool
	privateEmail  bool

	nonce      string
	audience   string
	kbIssuedAt time.Time
	kbSDHash   string

	jwk *sdjwt.JWK

	kbTyp string

	kbSigningKey ed25519.PrivateKey
}

func newVerifyFixture(
	t *testing.T,
	mutate func(*fixtureOptions),
) *verifyFixture {
	t.Helper()

	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	browserPublic, browserPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	options := fixtureOptions{
		email:         testEmail,
		emailVerified: true,
		privateEmail:  true,
		nonce:         testNonce,
		audience:      testAudience,
		kbIssuedAt:    time.Now(),
		kbTyp:         "kb+jwt",
	}

	if mutate != nil {
		mutate(&options)
	}

	issuerClaims := sdjwt.IssuerClaims{
		Email:          options.email,
		EmailVerified:  options.emailVerified,
		IsPrivateEmail: options.privateEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   testIssuer,
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	if options.jwk != nil {
		issuerClaims.CNF.JWK = *options.jwk
	} else {
		issuerClaims.CNF.JWK = sdjwt.JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X: base64.RawURLEncoding.EncodeToString(
				browserPublic,
			),
			Alg: "EdDSA",
		}
	}

	issuerToken := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		issuerClaims,
	)
	issuerToken.Header["typ"] = "evt+jwt"

	rawIssuerJWT, err := issuerToken.SignedString(issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}

	sdHash := options.kbSDHash
	if sdHash == "" {
		sdHash = calculateTestSDHash(rawIssuerJWT)
	}

	kbClaims := sdjwt.KeyBindingClaims{
		SDHash: sdHash,
		Nonce:  options.nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{
				options.audience,
			},
			IssuedAt: jwt.NewNumericDate(
				options.kbIssuedAt,
			),
		},
	}

	kbToken := jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		kbClaims,
	)
	kbToken.Header["typ"] = options.kbTyp

	kbSigningKey := options.kbSigningKey
	if kbSigningKey == nil {
		kbSigningKey = browserPrivate
	}

	rawKBJWT, err := kbToken.SignedString(kbSigningKey)
	if err != nil {
		t.Fatal(err)
	}

	return &verifyFixture{
		token: rawIssuerJWT + "~" + rawKBJWT,

		opts: evp_domain.VerifyOptions{
			Email:    testEmail,
			Nonce:    testNonce,
			Audience: testAudience,
			KBMaxAge: 5 * time.Minute,
		},

		issuerPublic:  issuerPublic,
		issuerPrivate: issuerPrivate,

		browserPublic:  browserPublic,
		browserPrivate: browserPrivate,

		config: &evp_domain.IssuerConfiguration{
			SigningAlgorithmsSupported: []string{
				"EdDSA",
			},
		},
	}
}

func (f *verifyFixture) resolver() *fakeIssuerResolver {
	return &fakeIssuerResolver{
		resolveIssuerFn: func(
			ctx context.Context,
			domain string,
		) (*evp_domain.IssuerMetadata, error) {
			return &evp_domain.IssuerMetadata{
				Issuer: testIssuer,
			}, nil
		},

		discoverIssuerFn: func(
			ctx context.Context,
			issuer *evp_domain.IssuerMetadata,
		) (*evp_domain.IssuerConfiguration, error) {
			return f.config, nil
		},

		keyfuncFn: func(
			config *evp_domain.IssuerConfiguration,
		) (jwt.Keyfunc, error) {
			return func(token *jwt.Token) (any, error) {
				return f.issuerPublic, nil
			}, nil
		},
	}
}

func calculateTestSDHash(issuerJWT string) string {
	sum := sha256.Sum256(
		[]byte(issuerJWT + "~"),
	)

	return base64.RawURLEncoding.EncodeToString(
		sum[:],
	)
}

func assertVerificationError(
	t *testing.T,
	err error,
	kind error,
	stage string,
) {
	t.Helper()

	if err == nil {
		t.Fatalf(
			"expected %v, got nil",
			kind,
		)
	}

	if !errors.Is(err, kind) {
		t.Fatalf(
			"expected errors.Is(%v), got %v",
			kind,
			err,
		)
	}

	var verificationErr *evp_domain.VerificationError
	if !errors.As(err, &verificationErr) {
		t.Fatalf(
			"expected *VerificationError, got %T: %v",
			err,
			err,
		)
	}

	if verificationErr.Stage != stage {
		t.Fatalf(
			"expected stage %q, got %q",
			stage,
			verificationErr.Stage,
		)
	}
}

func TestNewVerifier_CustomResolver(t *testing.T) {
	resolver := &fakeIssuerResolver{}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	if v.issuers != resolver {
		t.Fatal("expected provided resolver")
	}
}

func TestNewVerifier_DefaultResolver(t *testing.T) {
	v := NewVerifier(
		context.Background(),
		nil,
	)

	if v == nil {
		t.Fatal("expected verifier")
	}

	if v.issuers == nil {
		t.Fatal("expected default issuer resolver")
	}
}

func TestVerificationError_WithoutCause(t *testing.T) {
	err := verificationError(
		"email",
		evp_domain.ErrEmailNotVerified,
		nil,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrEmailNotVerified,
		"email",
	)
}

func TestVerificationError_WithCause(t *testing.T) {
	err := verificationError(
		"issuer_resolution",
		evp_domain.ErrIssuerResolution,
		errors.New("DNS failed"),
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrIssuerResolution,
		"issuer_resolution",
	)
}

func TestVerify_InputValidation(t *testing.T) {
	valid := evp_domain.VerifyOptions{
		Email:    testEmail,
		Nonce:    testNonce,
		Audience: testAudience,
	}

	tests := []struct {
		name  string
		token string
		opts  evp_domain.VerifyOptions
	}{
		{
			name:  "missing token",
			token: "",
			opts:  valid,
		},
		{
			name:  "whitespace token",
			token: "   ",
			opts:  valid,
		},
		{
			name:  "missing email",
			token: "token",
			opts: evp_domain.VerifyOptions{
				Nonce:    testNonce,
				Audience: testAudience,
			},
		},
		{
			name:  "missing nonce",
			token: "token",
			opts: evp_domain.VerifyOptions{
				Email:    testEmail,
				Audience: testAudience,
			},
		},
		{
			name:  "missing audience",
			token: "token",
			opts: evp_domain.VerifyOptions{
				Email: testEmail,
				Nonce: testNonce,
			},
		},
		{
			name:  "email without at",
			token: "token",
			opts: evp_domain.VerifyOptions{
				Email:    "invalid-email",
				Nonce:    testNonce,
				Audience: testAudience,
			},
		},
		{
			name:  "email missing local part",
			token: "token",
			opts: evp_domain.VerifyOptions{
				Email:    "@example.com",
				Nonce:    testNonce,
				Audience: testAudience,
			},
		},
		{
			name:  "email missing domain",
			token: "token",
			opts: evp_domain.VerifyOptions{
				Email:    "user@",
				Nonce:    testNonce,
				Audience: testAudience,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(
				context.Background(),
				&fakeIssuerResolver{},
			)

			_, err := v.Verify(
				context.Background(),
				tt.token,
				tt.opts,
			)

			assertVerificationError(
				t,
				err,
				evp_domain.ErrInvalidInput,
				"input",
			)
		})
	}
}

func TestVerify_LowercasesEmailDomain(t *testing.T) {
	f := newVerifyFixture(t, nil)

	f.opts.Email = "USER@EXAMPLE.COM"

	resolver := f.resolver()

	var receivedDomain string

	original := resolver.resolveIssuerFn

	resolver.resolveIssuerFn = func(
		ctx context.Context,
		domain string,
	) (*evp_domain.IssuerMetadata, error) {
		receivedDomain = domain

		return original(ctx, domain)
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	result, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if !result.Verified {
		t.Fatal("expected verified")
	}

	if receivedDomain != "example.com" {
		t.Fatalf(
			"expected example.com, got %q",
			receivedDomain,
		)
	}
}

func TestVerify_IssuerResolutionFailure(t *testing.T) {
	resolverErr := errors.New("DNS unavailable")

	resolver := &fakeIssuerResolver{
		resolveIssuerFn: func(
			context.Context,
			string,
		) (*evp_domain.IssuerMetadata, error) {
			return nil, resolverErr
		},
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	_, err := v.Verify(
		context.Background(),
		"does-not-matter",
		evp_domain.VerifyOptions{
			Email:    testEmail,
			Nonce:    testNonce,
			Audience: testAudience,
		},
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrIssuerResolution,
		"issuer_resolution",
	)
}

func TestVerify_MalformedPresentation(t *testing.T) {
	f := newVerifyFixture(t, nil)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		"definitely-not-an-sd-jwt",
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrMalformedToken,
		"presentation",
	)
}

func TestVerify_InvalidUnverifiedIssuerToken(t *testing.T) {
	f := newVerifyFixture(t, nil)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		"not-a-jwt~also-not-a-jwt",
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrInvalidIssuerToken,
		"issuer_token",
	)
}

func TestVerify_UnauthorizedIssuer(t *testing.T) {
	f := newVerifyFixture(t, nil)

	resolver := f.resolver()

	resolver.resolveIssuerFn = func(
		context.Context,
		string,
	) (*evp_domain.IssuerMetadata, error) {
		return &evp_domain.IssuerMetadata{
			Issuer: "https://attacker.example",
		}, nil
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrUnauthorizedIssuer,
		"issuer_authorization",
	)
}

func TestVerify_IssuerDiscoveryFailure(t *testing.T) {
	f := newVerifyFixture(t, nil)

	resolver := f.resolver()

	resolver.discoverIssuerFn = func(
		context.Context,
		*evp_domain.IssuerMetadata,
	) (*evp_domain.IssuerConfiguration, error) {
		return nil, errors.New(
			"discovery endpoint unavailable",
		)
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrIssuerDiscovery,
		"issuer_discovery",
	)
}

func TestVerify_KeyfuncFailure(t *testing.T) {
	f := newVerifyFixture(t, nil)

	resolver := f.resolver()

	resolver.keyfuncFn = func(
		*evp_domain.IssuerConfiguration,
	) (jwt.Keyfunc, error) {
		return nil, errors.New("JWKS failed")
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrIssuerDiscovery,
		"issuer_keys",
	)
}

func TestVerify_InvalidIssuerSignature(t *testing.T) {
	f := newVerifyFixture(t, nil)

	wrongPublic, _, err := ed25519.GenerateKey(
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}

	resolver := f.resolver()

	resolver.keyfuncFn = func(
		*evp_domain.IssuerConfiguration,
	) (jwt.Keyfunc, error) {
		return func(
			token *jwt.Token,
		) (any, error) {
			return wrongPublic, nil
		}, nil
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	_, err = v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrInvalidIssuerToken,
		"issuer_token",
	)
}

func TestVerify_EmailNotVerified(t *testing.T) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.emailVerified = false
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrEmailNotVerified,
		"email",
	)
}

func TestVerify_EmailMismatch(t *testing.T) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.email = "someone-else@example.com"
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrEmailMismatch,
		"email",
	)
}

func TestVerify_EmailComparisonIsCaseInsensitive(
	t *testing.T,
) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.email = "User@Example.COM"
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	result, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)
	if err != nil {
		t.Fatalf(
			"expected success, got %v",
			err,
		)
	}

	if !result.Verified {
		t.Fatal("expected verified")
	}
}

func TestVerify_InvalidConfirmationKey(t *testing.T) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.jwk = &sdjwt.JWK{
				Kty: "OKP",
				Crv: "Ed25519",
				X:   "%%%invalid%%%",
				Alg: "EdDSA",
			}
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrInvalidKeyBinding,
		"key_binding",
	)
}

func TestVerify_NonceMismatch(t *testing.T) {
	f := newVerifyFixture(t, nil)

	f.opts.Nonce = "different-nonce"

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrNonceMismatch,
		"key_binding",
	)
}

func TestVerify_AudienceMismatch(t *testing.T) {
	f := newVerifyFixture(t, nil)

	f.opts.Audience = "https://wrong.example.com"

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrAudienceMismatch,
		"key_binding",
	)
}

func TestVerify_TokenExpired(t *testing.T) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.kbIssuedAt = time.Now().Add(
				-10 * time.Minute,
			)
		},
	)

	f.opts.KBMaxAge = 5 * time.Minute

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrTokenExpired,
		"key_binding",
	)
}

func TestVerify_InvalidSDHash(t *testing.T) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.kbSDHash = "definitely-wrong"
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrInvalidPresentation,
		"key_binding",
	)
}

func TestVerify_InvalidKeyBinding(t *testing.T) {
	_, attackerPrivate, err := ed25519.GenerateKey(
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}

	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.kbSigningKey = attackerPrivate
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err = v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrInvalidKeyBinding,
		"key_binding",
	)
}

func TestVerify_InvalidKeyBindingTokenType(t *testing.T) {
	f := newVerifyFixture(
		t,
		func(o *fixtureOptions) {
			o.kbTyp = "JWT"
		},
	)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	_, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)

	assertVerificationError(
		t,
		err,
		evp_domain.ErrInvalidKeyBinding,
		"key_binding",
	)
}

func TestVerify_Success(t *testing.T) {
	f := newVerifyFixture(t, nil)

	v := NewVerifier(
		context.Background(),
		f.resolver(),
	)

	result, err := v.Verify(
		context.Background(),
		f.token,
		f.opts,
	)
	if err != nil {
		t.Fatalf(
			"expected success, got %v",
			err,
		)
	}

	if result == nil {
		t.Fatal("expected result")
	}

	if !result.Verified {
		t.Fatal("expected Verified=true")
	}

	if result.Email != testEmail {
		t.Fatalf(
			"expected email %q, got %q",
			testEmail,
			result.Email,
		)
	}

	if result.Issuer != testIssuer {
		t.Fatalf(
			"expected issuer %q, got %q",
			testIssuer,
			result.Issuer,
		)
	}

	if !result.PrivateEmail {
		t.Fatal("expected PrivateEmail=true")
	}
}

func TestVerify_ContextPassedToResolver(t *testing.T) {
	f := newVerifyFixture(t, nil)

	type contextKey string

	const key contextKey = "test"

	ctx := context.WithValue(
		context.Background(),
		key,
		"value",
	)

	resolver := f.resolver()

	original := resolver.resolveIssuerFn

	resolver.resolveIssuerFn = func(
		got context.Context,
		domain string,
	) (*evp_domain.IssuerMetadata, error) {
		if got.Value(key) != "value" {
			return nil, fmt.Errorf(
				"expected verification context",
			)
		}

		return original(got, domain)
	}

	v := NewVerifier(
		context.Background(),
		resolver,
	)

	result, err := v.Verify(
		ctx,
		f.token,
		f.opts,
	)
	if err != nil {
		t.Fatalf(
			"expected success, got %v",
			err,
		)
	}

	if !result.Verified {
		t.Fatal("expected verified")
	}
}
