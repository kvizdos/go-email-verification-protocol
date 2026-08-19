package evp_domain

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

type IssuerResolver interface {
	ResolveIssuer(
		ctx context.Context,
		emailDomain string,
	) (*IssuerMetadata, error)

	DiscoverIssuer(
		ctx context.Context,
		issuer *IssuerMetadata,
	) (*IssuerConfiguration, error)

	Keyfunc(
		config *IssuerConfiguration,
	) (jwt.Keyfunc, error)
}
