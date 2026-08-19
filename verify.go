package go_email_verification_protocol

import (
	"context"
	"time"

	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
	"github.com/kvizdos/go-email-verification-protocol/internal/verifier"
)

/*
 * Here, context is primarily used for the jwk keyfunc background
 * refresh system.
 */
var defaultVerifier = verifier.NewVerifier(context.Background(), nil)

const (
	DefaultEVTMaxAge = 5 * time.Minute
	DefaultKBMaxAge  = 5 * time.Minute
)

func Verify(
	ctx context.Context,
	token string,
	opts evp_domain.VerifyOptions,
) (*evp_domain.Result, error) {
	if opts.EVTMaxAge <= 0 {
		opts.EVTMaxAge = DefaultEVTMaxAge
	}

	if opts.KBMaxAge <= 0 {
		opts.KBMaxAge = DefaultKBMaxAge
	}

	return defaultVerifier.Verify(ctx, token, opts)
}

var (
	ErrInvalidInput       = evp_domain.ErrInvalidInput
	ErrIssuerResolution   = evp_domain.ErrIssuerResolution
	ErrIssuerDiscovery    = evp_domain.ErrIssuerDiscovery
	ErrUnauthorizedIssuer = evp_domain.ErrUnauthorizedIssuer
	ErrMalformedToken     = evp_domain.ErrMalformedToken
	ErrInvalidIssuerToken = evp_domain.ErrInvalidIssuerToken
	ErrEmailMismatch      = evp_domain.ErrEmailMismatch
	ErrEmailNotVerified   = evp_domain.ErrEmailNotVerified
	ErrInvalidKeyBinding  = evp_domain.ErrInvalidKeyBinding
	ErrNonceMismatch      = evp_domain.ErrNonceMismatch
	ErrAudienceMismatch   = evp_domain.ErrAudienceMismatch
	ErrTokenExpired       = evp_domain.ErrTokenExpired
)
