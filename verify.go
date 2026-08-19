package go_email_verification_protocol

import (
	"context"

	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
	"github.com/kvizdos/go-email-verification-protocol/internal/verifier"
)

var defaultVerifier = verifier.NewVerifier(context.TODO(), nil)

func Verify(
	ctx context.Context,
	token string,
	opts evp_domain.VerifyOptions,
) (*evp_domain.Result, error) {
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
