package verifier

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
)

type fakeIssuerResolver struct {
	resolveIssuerFn  func(context.Context, string) (*evp_domain.IssuerMetadata, error)
	discoverIssuerFn func(context.Context, *evp_domain.IssuerMetadata) (*evp_domain.IssuerConfiguration, error)
	keyfuncFn        func(*evp_domain.IssuerConfiguration) (jwt.Keyfunc, error)
}

func (f *fakeIssuerResolver) ResolveIssuer(
	ctx context.Context,
	domain string,
) (*evp_domain.IssuerMetadata, error) {
	if f.resolveIssuerFn == nil {
		return nil, errors.New(
			"fakeIssuerResolver.ResolveIssuer not configured",
		)
	}

	return f.resolveIssuerFn(ctx, domain)
}

func (f *fakeIssuerResolver) DiscoverIssuer(
	ctx context.Context,
	issuer *evp_domain.IssuerMetadata,
) (*evp_domain.IssuerConfiguration, error) {
	if f.discoverIssuerFn == nil {
		return nil, errors.New(
			"fakeIssuerResolver.DiscoverIssuer not configured",
		)
	}

	return f.discoverIssuerFn(ctx, issuer)
}

func (f *fakeIssuerResolver) Keyfunc(
	config *evp_domain.IssuerConfiguration,
) (jwt.Keyfunc, error) {
	if f.keyfuncFn == nil {
		return nil, errors.New(
			"fakeIssuerResolver.Keyfunc not configured",
		)
	}

	return f.keyfuncFn(config)
}
