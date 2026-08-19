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

const (
	maxResponseSize = 1 << 20 // 1 MB

	// JWKS keyfunc cache.
	defaultKeyfuncCacheSize = 128
	defaultKeyfuncIdleTTL   = 1 * time.Hour

	// DNS + discovery caches.
	defaultIssuerCacheSize   = 512
	defaultDNSCacheTTL       = 5 * time.Minute
	defaultDiscoveryCacheTTL = 5 * time.Minute
	defaultDNSLookupTimeout  = 5 * time.Second
	defaultDiscoveryTimeout  = 10 * time.Second

	// Bounds the amount of attacker-controlled outbound work
	// that may happen simultaneously.
	defaultMaxConcurrentDNS       = 32
	defaultMaxConcurrentDiscovery = 16
	defaultMaxConcurrentJWKSLoads = 16
)

type txtResolver interface {
	LookupTXT(
		ctx context.Context,
		name string,
	) ([]string, error)
}

//
// JWKS cache
//

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

//
// DNS issuer cache
//

type issuerCacheEntry struct {
	issuer    *evp_domain.IssuerMetadata
	expiresAt time.Time
}

type issuerLoad struct {
	done   chan struct{}
	issuer *evp_domain.IssuerMetadata
	err    error
}

//
// Issuer .well-known cache
//

type configCacheEntry struct {
	config    *evp_domain.IssuerConfiguration
	expiresAt time.Time
}

type configLoad struct {
	done   chan struct{}
	config *evp_domain.IssuerConfiguration
	err    error
}

type Resolver struct {
	resolver txtResolver
	client   *http.Client

	ctx context.Context

	mu sync.Mutex

	//
	// JWKS
	//
	keyfuncs map[string]*keyfuncCacheEntry
	loads    map[string]*keyfuncLoad

	keyfuncCacheSize int
	keyfuncIdleTTL   time.Duration

	jwksLoadSem chan struct{}

	//
	// DNS issuer resolution
	//
	issuerCache map[string]*issuerCacheEntry
	issuerLoads map[string]*issuerLoad

	//
	// Issuer metadata discovery
	//
	configCache map[string]*configCacheEntry
	configLoads map[string]*configLoad

	issuerCacheSize int

	dnsSem       chan struct{}
	discoverySem chan struct{}
}

func NewResolver(ctx context.Context) *Resolver {
	if ctx == nil {
		ctx = context.Background()
	}

	return &Resolver{
		resolver: net.DefaultResolver,
		client:   newSecureHTTPClient(),

		ctx: ctx,

		//
		// JWKS
		//
		keyfuncs: make(map[string]*keyfuncCacheEntry),
		loads:    make(map[string]*keyfuncLoad),

		keyfuncCacheSize: defaultKeyfuncCacheSize,
		keyfuncIdleTTL:   defaultKeyfuncIdleTTL,

		jwksLoadSem: make(
			chan struct{},
			defaultMaxConcurrentJWKSLoads,
		),

		//
		// DNS
		//
		issuerCache: make(map[string]*issuerCacheEntry),
		issuerLoads: make(map[string]*issuerLoad),

		//
		// Discovery
		//
		configCache: make(map[string]*configCacheEntry),
		configLoads: make(map[string]*configLoad),

		issuerCacheSize: defaultIssuerCacheSize,

		dnsSem: make(
			chan struct{},
			defaultMaxConcurrentDNS,
		),

		discoverySem: make(
			chan struct{},
			defaultMaxConcurrentDiscovery,
		),
	}
}

//
// DNS issuer resolution
//

func (r *Resolver) ResolveIssuer(
	ctx context.Context,
	emailDomain string,
) (*evp_domain.IssuerMetadata, error) {
	emailDomain = strings.ToLower(
		strings.TrimSpace(emailDomain),
	)

	if emailDomain == "" {
		return nil, errors.New(
			"email domain is required",
		)
	}

	now := time.Now()

	r.mu.Lock()

	r.removeExpiredIssuerCacheLocked(now)

	//
	// Cache hit.
	//
	if entry, ok := r.issuerCache[emailDomain]; ok {
		result := cloneIssuerMetadata(entry.issuer)

		r.mu.Unlock()

		return result, nil
	}

	//
	// Another goroutine is already resolving this domain.
	//
	if load, ok := r.issuerLoads[emailDomain]; ok {
		r.mu.Unlock()

		select {
		case <-load.done:
			if load.err != nil {
				return nil, load.err
			}

			return cloneIssuerMetadata(load.issuer), nil

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	load := &issuerLoad{
		done: make(chan struct{}),
	}

	r.issuerLoads[emailDomain] = load

	r.mu.Unlock()

	//
	// Globally bound fresh DNS work.
	//
	select {
	case r.dnsSem <- struct{}{}:
		defer func() {
			<-r.dnsSem
		}()

	case <-ctx.Done():
		r.finishIssuerLoad(
			emailDomain,
			load,
			nil,
			ctx.Err(),
		)

		return nil, ctx.Err()
	}

	//
	// LookupTXT otherwise has no independent timeout if the caller
	// supplied a context without a deadline.
	//
	lookupCtx, cancel := context.WithTimeout(
		ctx,
		defaultDNSLookupTimeout,
	)
	defer cancel()

	result, err := r.resolveIssuerUncached(
		lookupCtx,
		emailDomain,
	)

	r.finishIssuerLoad(
		emailDomain,
		load,
		result,
		err,
	)

	return result, err
}

func (r *Resolver) resolveIssuerUncached(
	ctx context.Context,
	emailDomain string,
) (*evp_domain.IssuerMetadata, error) {
	name := "_email-verification." + emailDomain

	records, err := r.resolver.LookupTXT(
		ctx,
		name,
	)
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

		3.1 DNS Delegation:

		There MUST be only one TXT record for
		_email-verification.$EMAIL_DOMAIN.
	*/
	if len(records) != 1 {
		return nil, fmt.Errorf(
			"%w: multiple records found",
			ErrNoIssuerFound,
		)
	}

	record := strings.TrimSpace(records[0])

	/*
		3.1 DNS Delegation:

		The contents of the record MUST start with iss=
		followed by the issuer identifier.
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

	//
	// Validate the issuer identifier now, but preserve its original
	// representation. This lets us support both:
	//
	//     issuer.example
	//
	// and current Chrome/Gmail-style:
	//
	//     https://issuer.example
	//
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

func (r *Resolver) finishIssuerLoad(
	emailDomain string,
	load *issuerLoad,
	result *evp_domain.IssuerMetadata,
	err error,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.issuerLoads, emailDomain)

	if err == nil && result != nil {
		load.issuer = cloneIssuerMetadata(result)

		if r.issuerCacheSize > 0 {
			now := time.Now()

			r.removeExpiredIssuerCacheLocked(now)
			r.makeIssuerCacheRoomLocked()

			r.issuerCache[emailDomain] = &issuerCacheEntry{
				issuer: cloneIssuerMetadata(result),
				expiresAt: now.Add(
					defaultDNSCacheTTL,
				),
			}
		}
	}

	load.err = err

	close(load.done)
}

func (r *Resolver) removeExpiredIssuerCacheLocked(
	now time.Time,
) {
	for key, entry := range r.issuerCache {
		if now.Before(entry.expiresAt) {
			continue
		}

		delete(r.issuerCache, key)
	}
}

func (r *Resolver) makeIssuerCacheRoomLocked() {
	if r.issuerCacheSize <= 0 {
		return
	}

	for len(r.issuerCache) >= r.issuerCacheSize {
		//
		// Exact LRU behavior is unnecessary here.
		// We need bounded memory, not perfect replacement policy.
		//
		for key := range r.issuerCache {
			delete(r.issuerCache, key)
			break
		}
	}
}

//
// Issuer metadata discovery
//

func (r *Resolver) DiscoverIssuer(
	ctx context.Context,
	issuer *evp_domain.IssuerMetadata,
) (*evp_domain.IssuerConfiguration, error) {
	if issuer == nil ||
		strings.TrimSpace(issuer.Issuer) == "" {
		return nil, errors.New(
			"issuer is required",
		)
	}

	iss, err := CanonicalIssuer(
		issuer.Issuer,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid issuer %q: %w",
			issuer.Issuer,
			err,
		)
	}

	now := time.Now()

	r.mu.Lock()

	r.removeExpiredConfigCacheLocked(now)

	//
	// Cache hit.
	//
	if entry, ok := r.configCache[iss]; ok {
		config := cloneIssuerConfiguration(
			entry.config,
		)

		r.mu.Unlock()

		return config, nil
	}

	//
	// Another goroutine is already fetching this issuer's
	// metadata.
	//
	if load, ok := r.configLoads[iss]; ok {
		r.mu.Unlock()

		select {
		case <-load.done:
			if load.err != nil {
				return nil, load.err
			}

			return cloneIssuerConfiguration(
				load.config,
			), nil

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	load := &configLoad{
		done: make(chan struct{}),
	}

	r.configLoads[iss] = load

	r.mu.Unlock()

	//
	// Globally bound fresh discovery HTTP work.
	//
	select {
	case r.discoverySem <- struct{}{}:
		defer func() {
			<-r.discoverySem
		}()

	case <-ctx.Done():
		r.finishConfigLoad(
			iss,
			load,
			nil,
			ctx.Err(),
		)

		return nil, ctx.Err()
	}

	discoveryCtx, cancel := context.WithTimeout(
		ctx,
		defaultDiscoveryTimeout,
	)
	defer cancel()

	config, err := r.discoverIssuerUncached(
		discoveryCtx,
		iss,
	)

	r.finishConfigLoad(
		iss,
		load,
		config,
		err,
	)

	return config, err
}

func (r *Resolver) discoverIssuerUncached(
	ctx context.Context,
	canonicalIssuer string,
) (*evp_domain.IssuerConfiguration, error) {
	discoveryURL, err := url.Parse(
		"https://" +
			canonicalIssuer +
			"/.well-known/email-verification",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid issuer discovery URL: %w",
			err,
		)
	}

	if err := validateOutboundURL(
		discoveryURL,
	); err != nil {
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

	req.Header.Set(
		"Accept",
		"application/json",
	)

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

	//
	// Read maxResponseSize + 1 so we can distinguish a response
	// that is exactly the limit from one that exceeds it.
	//
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

	if err := json.Unmarshal(
		body,
		&config,
	); err != nil {
		return nil, fmt.Errorf(
			"decode issuer configuration: %w",
			err,
		)
	}

	if strings.TrimSpace(config.JWKSURI) == "" {
		return nil, errors.New(
			"issuer configuration missing jwks_uri",
		)
	}

	if len(config.SigningAlgorithmsSupported) == 0 {
		/*
			If signing_alg_values_supported is omitted,
			EdDSA is the default.
		*/
		config.SigningAlgorithmsSupported = []string{
			"EdDSA",
		}
	} else {
		for _, alg := range config.SigningAlgorithmsSupported {
			/*
				The EVP draft explicitly forbids "none".
			*/
			if strings.EqualFold(
				strings.TrimSpace(alg),
				"none",
			) {
				return nil, errors.New(
					`signing algorithm "none" is forbidden`,
				)
			}
		}
	}

	jwksURL, err := url.Parse(
		config.JWKSURI,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}

	if err := validateOutboundURL(
		jwksURL,
	); err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}

	return &config, nil
}

func (r *Resolver) finishConfigLoad(
	issuer string,
	load *configLoad,
	config *evp_domain.IssuerConfiguration,
	err error,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.configLoads, issuer)

	if err == nil && config != nil {
		load.config = cloneIssuerConfiguration(
			config,
		)

		if r.issuerCacheSize > 0 {
			now := time.Now()

			r.removeExpiredConfigCacheLocked(now)
			r.makeConfigCacheRoomLocked()

			r.configCache[issuer] = &configCacheEntry{
				config: cloneIssuerConfiguration(
					config,
				),
				expiresAt: now.Add(
					defaultDiscoveryCacheTTL,
				),
			}
		}
	}

	load.err = err

	close(load.done)
}

func (r *Resolver) removeExpiredConfigCacheLocked(
	now time.Time,
) {
	for key, entry := range r.configCache {
		if now.Before(entry.expiresAt) {
			continue
		}

		delete(r.configCache, key)
	}
}

func (r *Resolver) makeConfigCacheRoomLocked() {
	if r.issuerCacheSize <= 0 {
		return
	}

	for len(r.configCache) >= r.issuerCacheSize {
		for key := range r.configCache {
			delete(r.configCache, key)
			break
		}
	}
}

//
// JWKS
//

func (r *Resolver) Keyfunc(
	config *evp_domain.IssuerConfiguration,
) (jwt.Keyfunc, error) {
	if config == nil {
		return nil, errors.New(
			"issuer configuration is required",
		)
	}

	if strings.TrimSpace(config.JWKSURI) == "" {
		return nil, errors.New(
			"jwks_uri is required",
		)
	}

	uri := config.JWKSURI

	//
	// Keyfunc may also be called independently of DiscoverIssuer,
	// so validate the outbound URL again here.
	//
	jwksURL, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}

	if err := validateOutboundURL(
		jwksURL,
	); err != nil {
		return nil, fmt.Errorf(
			"invalid jwks_uri: %w",
			err,
		)
	}

	now := time.Now()

	r.mu.Lock()

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
	// Same JWKS already being loaded.
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

	load := &keyfuncLoad{
		done: make(chan struct{}),
	}

	r.loads[uri] = load

	r.mu.Unlock()

	//
	// Bound simultaneous NEW JWKS loads.
	//
	select {
	case r.jwksLoadSem <- struct{}{}:
		defer func() {
			<-r.jwksLoadSem
		}()

	case <-r.ctx.Done():
		r.mu.Lock()

		delete(r.loads, uri)

		load.err = r.ctx.Err()
		close(load.done)

		r.mu.Unlock()

		return nil, r.ctx.Err()
	}

	//
	// Every cached remote keyfunc gets its own child context.
	// Canceling this context stops keyfunc's refresh goroutine
	// when the cache entry is evicted.
	//
	entryCtx, cancel := context.WithCancel(
		r.ctx,
	)

	jwksClient := withMaxResponseSize(
		r.client,
		maxJWKSResponseSize,
	)

	k, err := keyfunc.NewDefaultOverrideCtx(
		entryCtx,
		[]string{uri},
		keyfunc.Override{
			Client:      jwksClient,
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
	// Make room BEFORE inserting.
	//
	r.evictKeyfuncsLocked(1)

	entry := &keyfuncCacheEntry{
		keyfunc:  k.Keyfunc,
		cancel:   cancel,
		lastUsed: time.Now(),
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
		if now.Sub(entry.lastUsed) <=
			r.keyfuncIdleTTL {
			continue
		}

		delete(r.keyfuncs, uri)

		//
		// Stop keyfunc's background JWKS refresh goroutine.
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

	for len(r.keyfuncs)+needed >
		r.keyfuncCacheSize {
		var (
			oldestURI   string
			oldestEntry *keyfuncCacheEntry
		)

		for uri, entry := range r.keyfuncs {
			if oldestEntry == nil ||
				entry.lastUsed.Before(
					oldestEntry.lastUsed,
				) {
				oldestURI = uri
				oldestEntry = entry
			}
		}

		if oldestEntry == nil {
			return
		}

		delete(
			r.keyfuncs,
			oldestURI,
		)

		//
		// Removing the map entry alone is not enough:
		// cancel the refresh goroutine it owns.
		//
		oldestEntry.cancel()
	}
}

//
// Issuer canonicalization
//

// CanonicalIssuer converts either:
//
//	issuer.example
//
// or:
//
//	https://issuer.example
//
// into the same comparison/discovery authority:
//
//	issuer.example
//
// Ports are preserved:
//
//	https://issuer.example:8443
//
// becomes:
//
//	issuer.example:8443
//
// This intentionally separates the EVP issuer identifier from the
// HTTPS URL used to perform issuer discovery.
func CanonicalIssuer(
	raw string,
) (string, error) {
	raw = strings.TrimSpace(raw)

	if raw == "" {
		return "", errors.New(
			"issuer is required",
		)
	}

	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if !strings.EqualFold(
		u.Scheme,
		"https",
	) {
		return "", errors.New(
			"issuer must use https",
		)
	}

	if u.Host == "" {
		return "", errors.New(
			"issuer host is required",
		)
	}

	if u.User != nil {
		return "", errors.New(
			"issuer cannot contain user info",
		)
	}

	if u.Path != "" &&
		u.Path != "/" {
		return "", errors.New(
			"issuer cannot contain path",
		)
	}

	if u.RawQuery != "" ||
		u.Fragment != "" {
		return "", errors.New(
			"issuer cannot contain query or fragment",
		)
	}

	//
	// Hostname() strips brackets from IPv6 and strips the port.
	//
	host := strings.ToLower(
		strings.TrimSuffix(
			u.Hostname(),
			".",
		),
	)

	if host == "" {
		return "", errors.New(
			"issuer host is required",
		)
	}

	port := u.Port()

	if port != "" {
		return net.JoinHostPort(
			host,
			port,
		), nil
	}

	//
	// Preserve proper URL authority syntax for an IPv6 literal.
	//
	if strings.Contains(host, ":") {
		return "[" + host + "]", nil
	}

	return host, nil
}

//
// Safe cloning helpers.
//
// These prevent callers from mutating values stored in our caches.
//

func cloneIssuerMetadata(
	in *evp_domain.IssuerMetadata,
) *evp_domain.IssuerMetadata {
	if in == nil {
		return nil
	}

	out := *in

	return &out
}

func cloneIssuerConfiguration(
	in *evp_domain.IssuerConfiguration,
) *evp_domain.IssuerConfiguration {
	if in == nil {
		return nil
	}

	out := *in

	if in.SigningAlgorithmsSupported != nil {
		out.SigningAlgorithmsSupported = append(
			[]string(nil),
			in.SigningAlgorithmsSupported...,
		)
	}

	return &out
}
