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

type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

const (
	defaultKeyfuncCacheSize = 128
	defaultKeyfuncIdleTTL   = 1 * time.Hour
)

type keyfuncCacheEntry struct {
	keyfunc  jwt.Keyfunc
	cancel   context.CancelFunc
	lastUsed time.Time
}

type keyfuncLoad struct {
	done    chan struct{}
	keyfunc jwt.Keyfunc
	err     error
}

type Resolver struct {
	resolver txtResolver
	client   *http.Client

	ctx context.Context

	mu sync.Mutex

	keyfuncs map[string]*keyfuncCacheEntry
	loads    map[string]*keyfuncLoad

	keyfuncCacheSize int
	keyfuncIdleTTL   time.Duration
}

func NewResolver(ctx context.Context) *Resolver {
	return &Resolver{
		resolver: net.DefaultResolver,
		client:   newSecureHTTPClient(),

		ctx: ctx,

		keyfuncs: make(map[string]*keyfuncCacheEntry),
		loads:    make(map[string]*keyfuncLoad),

		keyfuncCacheSize: defaultKeyfuncCacheSize,
		keyfuncIdleTTL:   defaultKeyfuncIdleTTL,
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

	if _, err := CanonicalIssuer(rawIssuer); err != nil {
		return nil, fmt.Errorf(
			"%w: invalid issuer %q: %v",
			ErrNoIssuerFound,
			rawIssuer,
			err,
		)
	}
	return &evp_domain.IssuerMetadata{
		Issuer: rawIssuer,
	}, nil

}

func (r *Resolver) DiscoverIssuer(
	ctx context.Context,
	issuer *evp_domain.IssuerMetadata,
) (*evp_domain.IssuerConfiguration, error) {
	if issuer == nil || issuer.Issuer == "" {
		return nil, errors.New("issuer is required")
	}

	iss, err := CanonicalIssuer(issuer.Issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid issuer %q: %w",
			issuer.Issuer,
			err,
		)
	}

	discoveryURL, err := url.Parse("https://" + iss + "/.well-known/email-verification")
	if err != nil {
		return nil, fmt.Errorf(
			"invalid issuer discovery URL: %w",
			err,
		)
	}

	if err := validateOutboundURL(discoveryURL); err != nil {
		return nil, fmt.Errorf(
			"invalid issuer discovery URL: %w",
			err,
		)
	}

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

	body, err := io.ReadAll(
		io.LimitReader(
			resp.Body,
			maxResponseSize+1,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read issuer configuration: %w",
			err,
		)
	}

	if len(body) > maxResponseSize {
		return nil, errors.New(
			"issuer configuration exceeds maximum size",
		)
	}

	var config evp_domain.IssuerConfiguration

	if err := json.Unmarshal(body, &config); err != nil {
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
	} else {
		for _, alg := range config.SigningAlgorithmsSupported {
			/*
			 * signing_alg_values_supported - OPTIONAL. JSON array containing a list of the signing algorithms ("alg" values) supported by the issuer for both HTTP Message Signatures and issued EVTs. Algorithm identifiers MUST be from the IANA "JSON Web Signature and Encryption Algorithms" registry. If omitted, "EdDSA" is the default. "EdDSA" SHOULD be included in the supported algorithms list. The value "none" MUST NOT be used.
			 */
			if strings.ToLower(alg) == "none" {
				return nil, errors.New(
					"none algorithm is strictly forbidden",
				)
			}
		}
	}
	jwksURL, err := url.Parse(config.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}
	if err := validateOutboundURL(jwksURL); err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}

	return &config, nil
}

func (r *Resolver) Keyfunc(
	config *evp_domain.IssuerConfiguration,
) (jwt.Keyfunc, error) {
	if config == nil {
		return nil, errors.New(
			"issuer configuration is required",
		)
	}

	if config.JWKSURI == "" {
		return nil, errors.New(
			"jwks_uri is required",
		)
	}

	uri := config.JWKSURI
	now := time.Now()

	r.mu.Lock()

	//
	// Opportunistically remove entries which haven't been used
	// within the idle TTL.
	//
	r.removeExpiredKeyfuncsLocked(now)

	//
	// Cache hit.
	//
	if entry, ok := r.keyfuncs[uri]; ok {
		entry.lastUsed = now

		keyFunc := entry.keyfunc

		r.mu.Unlock()

		return keyFunc, nil
	}

	//
	// Someone else is already fetching this exact JWKS URI.
	//
	// Wait for that fetch instead of creating another HTTP request
	// and another refresh goroutine.
	//
	if load, ok := r.loads[uri]; ok {
		r.mu.Unlock()

		select {
		case <-load.done:
			return load.keyfunc, load.err

		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		}
	}

	//
	// Mark this URI as loading.
	//
	load := &keyfuncLoad{
		done: make(chan struct{}),
	}

	r.loads[uri] = load

	r.mu.Unlock()

	//
	// IMPORTANT:
	//
	// Give each cached keyfunc its own context. Eviction/expiration
	// can then stop its refresh goroutine without affecting any
	// other issuer.
	//
	entryCtx, cancel := context.WithCancel(r.ctx)

	k, err := keyfunc.NewDefaultOverrideCtx(
		entryCtx,
		[]string{uri},
		keyfunc.Override{
			Client:      r.client,
			HTTPTimeout: 10 * time.Second,
		},
	)

	if err != nil {
		cancel()

		err = fmt.Errorf(
			"failed to load issuer JWKS: %w",
			err,
		)
	}

	r.mu.Lock()

	delete(r.loads, uri)

	if err != nil {
		load.err = err

		close(load.done)

		r.mu.Unlock()

		cancel()
		return nil, err
	}

	//
	// Make room before adding the new entry.
	//
	r.evictKeyfuncsLocked(1)

	entry := &keyfuncCacheEntry{
		keyfunc:  k.Keyfunc,
		cancel:   cancel,
		lastUsed: now,
	}

	r.keyfuncs[uri] = entry

	load.keyfunc = entry.keyfunc

	close(load.done)

	r.mu.Unlock()

	return entry.keyfunc, nil
}

func (r *Resolver) removeExpiredKeyfuncsLocked(
	now time.Time,
) {
	if r.keyfuncIdleTTL <= 0 {
		return
	}

	for uri, entry := range r.keyfuncs {
		if now.Sub(entry.lastUsed) <= r.keyfuncIdleTTL {
			continue
		}

		delete(r.keyfuncs, uri)

		//
		// Stops keyfunc's background refresh goroutine.
		//
		entry.cancel()
	}
}

func (r *Resolver) evictKeyfuncsLocked(
	needed int,
) {
	if r.keyfuncCacheSize <= 0 {
		return
	}

	for len(r.keyfuncs)+needed > r.keyfuncCacheSize {
		var (
			oldestURI   string
			oldestEntry *keyfuncCacheEntry
		)

		for uri, entry := range r.keyfuncs {
			if oldestEntry == nil ||
				entry.lastUsed.Before(oldestEntry.lastUsed) {
				oldestURI = uri
				oldestEntry = entry
			}
		}

		if oldestEntry == nil {
			return
		}

		delete(r.keyfuncs, oldestURI)

		//
		// This is the critical part. Don't merely remove it from
		// the map: terminate the refresh goroutine it owns.
		//
		oldestEntry.cancel()
	}
}

func CanonicalIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)

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
		return "", errors.New("issuer host is required")
	}

	if u.User != nil ||
		(u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" ||
		u.Fragment != "" {
		return "", errors.New("invalid issuer")
	}

	return strings.ToLower(u.Host), nil
}
