package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
)

var _ evp_domain.IssuerResolver = (*Resolver)(nil)

const maxResponseSize = 1 << 20 // 1 MB

type Resolver struct {
	resolver *net.Resolver
	client   *http.Client

	ctx context.Context

	mu       sync.Mutex
	keyfuncs map[string]jwt.Keyfunc
}

func NewResolver(ctx context.Context) *Resolver {
	return &Resolver{
		resolver: net.DefaultResolver,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		ctx:      ctx,
		keyfuncs: make(map[string]jwt.Keyfunc),
	}
}

func (r *Resolver) ResolveIssuer(
	ctx context.Context,
	emailDomain string,
) (*evp_domain.IssuerMetadata, error) {
	emailDomain = strings.TrimSpace(strings.ToLower(emailDomain))
	if emailDomain == "" {
		return nil, errors.New("email domain is required")
	}

	name := "_email-verification." + emailDomain

	records, err := r.resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: lookup %s: %w",
			ErrFailedLookup,
			name,
			err,
		)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf(
			"%w: no issuer found for %s",
			ErrNoIssuerFound,
			emailDomain,
		)
	}

	/*
		https://datatracker.ietf.org/doc/draft-hardt-email-verification/
		3.1.  DNS Delegation
		The email domain delegates email verification to an issuer via a DNS
		TXT record.  Given an email address, parse the email domain
		(EMAIL_DOMAIN) and look up the `TXT` record for `_email-
		verification.EMAIL_DOMAIN.  The contents of the record MUST start
		withiss=followed by the issuer identifier.  There MUST be only
		one TXT record for _email-verification.$EMAIL_DOMAIN`.
	*/
	if len(records) != 1 {
		return nil, fmt.Errorf(
			"%w: multiple records found",
			ErrNoIssuerFound,
		)
	}

	record := strings.TrimSpace(records[0])

	/*
	 * 3.1 DNS Delegation
	 The contents of the record MUST start withiss=
	*/
	if !strings.HasPrefix(record, "iss=") {
		return nil, fmt.Errorf(
			"%w: invalid issuer record %q",
			ErrNoIssuerFound,
			record,
		)
	}

	rawIssuer := strings.TrimSpace(
		strings.TrimPrefix(record, "iss="),
	)

	if rawIssuer == "" {
		return nil, fmt.Errorf(
			"%w: issuer record %q is empty",
			ErrNoIssuerFound,
			record,
		)
	}

	issuer, err := normalizeIssuer(rawIssuer)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: invalid issuer %q: %w",
			ErrNoIssuerFound,
			rawIssuer,
			err,
		)
	}

	return &evp_domain.IssuerMetadata{
		Issuer: issuer,
	}, nil

}

func (r *Resolver) DiscoverIssuer(
	ctx context.Context,
	issuer *evp_domain.IssuerMetadata,
) (*evp_domain.IssuerConfiguration, error) {
	if issuer == nil || issuer.Issuer == "" {
		return nil, errors.New("issuer is required")
	}

	issuerURL, err := url.Parse(issuer.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL: %w", err)
	}

	if issuerURL.Scheme != "https" {
		return nil, errors.New("issuer must use https")
	}

	if issuerURL.Host == "" {
		return nil, errors.New("issuer host is required")
	}

	discoveryURL := issuerURL.ResolveReference(
		&url.URL{
			Path: "/.well-known/email-verification",
		},
	)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		discoveryURL.String(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create issuer discovery request: %w",
			err,
		)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(
			"issuer discovery request failed: %w",
			err,
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"issuer discovery returned HTTP %d",
			resp.StatusCode,
		)
	}

	var config evp_domain.IssuerConfiguration

	decoder := json.NewDecoder(
		io.LimitReader(resp.Body, maxResponseSize),
	)

	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf(
			"decode issuer configuration: %w",
			err,
		)
	}

	if config.JWKSURI == "" {
		return nil, errors.New(
			"issuer configuration missing jwks_uri",
		)
	}

	if len(config.SigningAlgorithmsSupported) == 0 {
		/*
			https://datatracker.ietf.org/doc/draft-hardt-email-verification/
			2.4  Token Request
			The browser generates a fresh private/public key pair.  The
			browser SHOULD select an algorithm from the issuer's
			signing_alg_values_supported array, or use "EdDSA" if not
			present.
		*/
		config.SigningAlgorithmsSupported = []string{"EdDSA"}
	}
	jwksURL, err := url.Parse(config.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}

	if jwksURL.Scheme != "https" || jwksURL.Host == "" {
		return nil, errors.New(
			"jwks_uri must be an absolute HTTPS URL",
		)
	}

	return &config, nil
}

func (r *Resolver) Keyfunc(
	config *evp_domain.IssuerConfiguration,
) (jwt.Keyfunc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if keyFunc, ok := r.keyfuncs[config.JWKSURI]; ok {
		return keyFunc, nil
	}

	k, err := keyfunc.NewDefaultCtx(
		r.ctx,
		[]string{config.JWKSURI},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load issuer JWKS: %w", err)
	}

	r.keyfuncs[config.JWKSURI] = k.Keyfunc

	return k.Keyfunc, nil
}

func normalizeIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

	//
	// EVP DNS currently returns:
	//
	//     iss=accounts.google.com
	//
	// while the EVT uses:
	//
	//     iss=https://accounts.google.com
	//
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if u.Scheme != "https" {
		return "", errors.New("issuer must use https")
	}

	if u.Host == "" {
		return "", errors.New("issuer host is missing")
	}

	if u.User != nil {
		return "", errors.New("issuer cannot contain user info")
	}

	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New(
			"issuer cannot contain query or fragment",
		)
	}

	// Normalize the simple origin form EVP currently uses.
	return strings.TrimSuffix(u.String(), "/"), nil
}
