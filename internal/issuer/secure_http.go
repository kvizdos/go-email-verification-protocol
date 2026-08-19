package issuer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

const maxRedirects = 3

var blockedPrefixes = []netip.Prefix{
	// "This host" / software network.
	netip.MustParsePrefix("0.0.0.0/8"),

	// Carrier-grade NAT / shared address space.
	// Not technically RFC1918, but it may still route internally.
	netip.MustParsePrefix("100.64.0.0/10"),
}

func newSecureHTTPClient() *http.Client {
	resolver := net.DefaultResolver

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	// Don't let an environment-configured proxy bypass our target-IP
	// validation by resolving the destination on our behalf.
	transport.Proxy = nil

	transport.DialContext = func(
		ctx context.Context,
		network string,
		addr string,
	) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid outbound address %q: %w",
				addr,
				err,
			)
		}

		ips, err := resolveSafeIPs(ctx, resolver, host)
		if err != nil {
			return nil, err
		}

		var lastErr error

		for _, ip := range ips {
			target := net.JoinHostPort(
				ip.String(),
				port,
			)

			conn, err := dialer.DialContext(
				ctx,
				network,
				target,
			)
			if err == nil {
				return conn, nil
			}

			lastErr = err
		}

		if lastErr != nil {
			return nil, lastErr
		}

		return nil, errors.New(
			"no acceptable IP addresses resolved",
		)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,

		CheckRedirect: func(
			req *http.Request,
			via []*http.Request,
		) error {
			if len(via) >= maxRedirects {
				return errors.New(
					"too many redirects",
				)
			}

			if err := validateOutboundURL(req.URL); err != nil {
				return fmt.Errorf(
					"unsafe redirect destination: %w",
					err,
				)
			}

			return nil
		},
	}
}

func validateOutboundURL(u *url.URL) error {
	if u == nil {
		return errors.New("URL is required")
	}

	if u.Scheme != "https" {
		return fmt.Errorf(
			"URL must use HTTPS, got %q",
			u.Scheme,
		)
	}

	if u.Hostname() == "" {
		return errors.New(
			"URL hostname is required",
		)
	}

	if u.User != nil {
		return errors.New(
			"URL must not contain user info",
		)
	}

	// Ports are intentionally allowed.
	//
	// https://issuer.example:8443/... is fine.

	return nil
}

func resolveSafeIPs(
	ctx context.Context,
	resolver *net.Resolver,
	host string,
) ([]netip.Addr, error) {
	// If the hostname itself is an IP literal, don't perform DNS.
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()

		if err := validateOutboundIP(ip); err != nil {
			return nil, err
		}

		return []netip.Addr{ip}, nil
	}

	ips, err := resolver.LookupNetIP(
		ctx,
		"ip",
		host,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve %q: %w",
			host,
			err,
		)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf(
			"host %q resolved to no addresses",
			host,
		)
	}

	safe := make([]netip.Addr, 0, len(ips))

	for _, ip := range ips {
		ip = ip.Unmap()

		// Be conservative: if a hostname resolves to ANY private /
		// local address, reject the hostname completely rather than
		// simply selecting one of its public answers.
		if err := validateOutboundIP(ip); err != nil {
			return nil, fmt.Errorf(
				"host %q resolved to unsafe address %s: %w",
				host,
				ip,
				err,
			)
		}

		safe = append(safe, ip)
	}

	return safe, nil
}

func validateOutboundIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid IP address")
	}

	ip = ip.Unmap()

	if ip.Zone() != "" {
		return errors.New(
			"scoped IP addresses are not allowed",
		)
	}

	switch {
	case ip.IsUnspecified():
		return errors.New(
			"unspecified IP addresses are not allowed",
		)

	case ip.IsLoopback():
		return errors.New(
			"loopback IP addresses are not allowed",
		)

	case ip.IsPrivate():
		return errors.New(
			"private IP addresses are not allowed",
		)

	case ip.IsLinkLocalUnicast():
		return errors.New(
			"link-local IP addresses are not allowed",
		)

	case ip.IsLinkLocalMulticast():
		return errors.New(
			"link-local multicast addresses are not allowed",
		)

	case ip.IsInterfaceLocalMulticast():
		return errors.New(
			"interface-local multicast addresses are not allowed",
		)

	case ip.IsMulticast():
		return errors.New(
			"multicast IP addresses are not allowed",
		)
	}

	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return fmt.Errorf(
				"address %s is in blocked range %s",
				ip,
				prefix,
			)
		}
	}

	return nil
}
