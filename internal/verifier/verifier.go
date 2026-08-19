package verifier

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
	"github.com/kvizdos/go-email-verification-protocol/internal/issuer"
	"github.com/kvizdos/go-email-verification-protocol/internal/sdjwt"
)

func NewVerifier(ctx context.Context, issuers evp_domain.IssuerResolver) *verifier {
	if issuers == nil {
		return &verifier{
			issuers: issuer.NewResolver(ctx),
		}
	}

	return &verifier{
		issuers: issuers,
	}
}

type verifier struct {
	issuers evp_domain.IssuerResolver
}

func verificationError(stage string, kind error, cause error) error {
	if cause == nil {
		return &evp_domain.VerificationError{
			Stage: stage,
			Err:   kind,
		}
	}

	return &evp_domain.VerificationError{
		Stage: stage,
		Err:   fmt.Errorf("%w: %v", kind, cause),
	}
}

func (v *verifier) Verify(
	ctx context.Context,
	token string,
	opts evp_domain.VerifyOptions,
) (*evp_domain.Result, error) {
	// Input validation
	if strings.TrimSpace(token) == "" {
		return nil, verificationError(
			"input",
			evp_domain.ErrInvalidInput,
			errors.New("token is required"),
		)
	}

	if strings.TrimSpace(opts.Email) == "" {
		return nil, verificationError(
			"input",
			evp_domain.ErrInvalidInput,
			errors.New("email is required"),
		)
	}

	if strings.TrimSpace(opts.Nonce) == "" {
		return nil, verificationError(
			"input",
			evp_domain.ErrInvalidInput,
			errors.New("nonce is required"),
		)
	}

	if strings.TrimSpace(opts.Audience) == "" {
		return nil, verificationError(
			"input",
			evp_domain.ErrInvalidInput,
			errors.New("audience is required"),
		)
	}

	at := strings.LastIndex(opts.Email, "@")
	if at <= 0 || at == len(opts.Email)-1 {
		return nil, verificationError(
			"input",
			evp_domain.ErrInvalidInput,
			errors.New("invalid email address"),
		)
	}

	emailDomain := strings.ToLower(opts.Email[at+1:])

	// Resolve the issuer authorized by the email domain.
	authorizedIssuer, err := v.issuers.ResolveIssuer(ctx, emailDomain)
	if err != nil {
		return nil, verificationError(
			"issuer_resolution",
			evp_domain.ErrIssuerResolution,
			err,
		)
	}

	// Parse SD-JWT + KB presentation.
	presentation, err := sdjwt.Parse(token)
	if err != nil {
		return nil, verificationError(
			"presentation",
			evp_domain.ErrMalformedToken,
			err,
		)
	}

	// Read the issuer claim before signature validation only so we know
	// whether it matches the issuer authorized by DNS.
	unverified, err := sdjwt.ParseIssuerClaimsUnverified(
		presentation.IssuerJWT,
	)
	if err != nil {
		return nil, verificationError(
			"issuer_token",
			evp_domain.ErrInvalidIssuerToken,
			err,
		)
	}

	if unverified.Issuer != authorizedIssuer.Issuer {
		return nil, verificationError(
			"issuer_authorization",
			evp_domain.ErrUnauthorizedIssuer,
			fmt.Errorf(
				"token issuer %q does not match authorized issuer %q",
				unverified.Issuer,
				authorizedIssuer.Issuer,
			),
		)
	}

	// Discover issuer metadata.
	config, err := v.issuers.DiscoverIssuer(ctx, authorizedIssuer)
	if err != nil {
		return nil, verificationError(
			"issuer_discovery",
			evp_domain.ErrIssuerDiscovery,
			err,
		)
	}

	// Resolve the issuer's signing keys.
	keyFunc, err := v.issuers.Keyfunc(config)
	if err != nil {
		return nil, verificationError(
			"issuer_keys",
			evp_domain.ErrIssuerDiscovery,
			err,
		)
	}

	// Cryptographically verify the issuer JWT.
	claims, err := sdjwt.VerifyIssuerJWT(
		presentation,
		config,
		keyFunc,
	)
	if err != nil {
		return nil, verificationError(
			"issuer_token",
			evp_domain.ErrInvalidIssuerToken,
			err,
		)
	}

	// EVP requires email_verified=true.
	if !claims.EmailVerified {
		return nil, verificationError(
			"email",
			evp_domain.ErrEmailNotVerified,
			nil,
		)
	}

	if !strings.EqualFold(claims.Email, opts.Email) {
		return nil, verificationError(
			"email",
			evp_domain.ErrEmailMismatch,
			fmt.Errorf(
				"token contains %q, expected %q",
				claims.Email,
				opts.Email,
			),
		)
	}

	// Extract browser confirmation key.
	key, alg, err := claims.ConfirmationPublicKey()
	if err != nil {
		return nil, verificationError(
			"key_binding",
			evp_domain.ErrInvalidKeyBinding,
			fmt.Errorf("invalid confirmation key: %w", err),
		)
	}

	// Verify KB-JWT signature, nonce, audience, timestamp and sd_hash.
	if err := sdjwt.VerifyKeyBinding(
		presentation,
		key,
		alg,
		opts.Nonce,
		opts.Audience,
		opts.MaxAge,
	); err != nil {
		kind := evp_domain.ErrInvalidKeyBinding

		switch {
		case errors.Is(err, sdjwt.ErrNonceMismatch):
			kind = evp_domain.ErrNonceMismatch

		case errors.Is(err, sdjwt.ErrAudienceMismatch):
			kind = evp_domain.ErrAudienceMismatch

		case errors.Is(err, sdjwt.ErrTokenExpired):
			kind = evp_domain.ErrTokenExpired

		case errors.Is(err, sdjwt.ErrInvalidPresentation),
			errors.Is(err, sdjwt.ErrInvalidSDHash):
			kind = evp_domain.ErrInvalidPresentation
		}

		return nil, verificationError(
			"key_binding",
			kind,
			err,
		)
	}

	return &evp_domain.Result{
		Verified:     true,
		Email:        claims.Email,
		Issuer:       claims.Issuer,
		PrivateEmail: claims.IsPrivateEmail,
	}, nil
}
