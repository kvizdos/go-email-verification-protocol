package issuer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
)

type fakeTXTResolver struct {
	records []string
	err     error
	name    string
}

func (f *fakeTXTResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	f.name = name
	return f.records, f.err
}

func TestResolveIssuer(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		records   []string
		lookupErr error

		wantIssuer string
		wantErr    error
	}{
		{
			name:       "valid",
			domain:     "gmail.com",
			records:    []string{"iss=accounts.google.com"},
			wantIssuer: "accounts.google.com",
		},
		{
			name:       "trims whitespace",
			domain:     " gmail.com ",
			records:    []string{"  iss=accounts.google.com  "},
			wantIssuer: "accounts.google.com",
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: errors.New("email domain is required"),
		},
		{
			name:      "lookup failure",
			domain:    "example.com",
			lookupErr: errors.New("dns failed"),
			wantErr:   ErrFailedLookup,
		},
		{
			name:    "no records",
			domain:  "example.com",
			records: nil,
			wantErr: ErrNoIssuerFound,
		},
		{
			name:   "multiple records",
			domain: "example.com",
			records: []string{
				"iss=issuer1.example",
				"iss=issuer2.example",
			},
			wantErr: ErrNoIssuerFound,
		},
		{
			name:    "wrong prefix",
			domain:  "example.com",
			records: []string{"foo=issuer.example"},
			wantErr: ErrNoIssuerFound,
		},
		{
			name:    "empty issuer",
			domain:  "example.com",
			records: []string{"iss="},
			wantErr: ErrNoIssuerFound,
		},
		{
			name:    "http issuer rejected",
			domain:  "example.com",
			records: []string{"iss=http://issuer.example"},
			wantErr: ErrNoIssuerFound,
		},
		{
			name:       "normalizes domain to lowercase",
			domain:     "GMAIL.COM",
			records:    []string{"iss=accounts.google.com"},
			wantIssuer: "accounts.google.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeTXTResolver{
				records: tt.records,
				err:     tt.lookupErr,
			}

			r := NewResolver(context.Background())
			r.resolver = fake

			got, err := r.ResolveIssuer(
				context.Background(),
				tt.domain,
			)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected %v, got nil", tt.wantErr)
				}

				if !errors.Is(err, tt.wantErr) &&
					err.Error() != tt.wantErr.Error() {
					t.Fatalf("expected %v, got %v", tt.wantErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}

			if got.Issuer != tt.wantIssuer {
				t.Fatalf(
					"expected %q, got %q",
					tt.wantIssuer,
					got.Issuer,
				)
			}

			wantLookup := "_email-verification." +
				strings.ToLower(strings.TrimSpace(tt.domain))

			if fake.name != wantLookup {
				t.Fatalf(
					"expected lookup %q, got %q",
					wantLookup,
					fake.name,
				)
			}
		})
	}
}

func TestDiscoverIssuer_Valid(t *testing.T) {
	var server *httptest.Server

	server = httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET, got %s", r.Method)
			}

			if r.URL.Path != "/.well-known/email-verification" {
				t.Fatalf("unexpected path %q", r.URL.Path)
			}

			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Fatalf("unexpected Accept %q", got)
			}
			fmt.Fprintf(w, `{
				"jwks_uri": %q,
				"signing_alg_values_supported": ["EdDSA"]
			}`, server.URL+"/jwks")
		}),
	)
	defer server.Close()

	r := NewResolver(context.Background())
	r.client = server.Client()

	config, err := r.DiscoverIssuer(
		context.Background(),
		&evp_domain.IssuerMetadata{
			Issuer: server.URL,
		},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if config.JWKSURI != server.URL+"/jwks" {
		t.Fatalf(
			"unexpected jwks_uri %q",
			config.JWKSURI,
		)
	}
}

func TestDiscoverIssuer_DefaultsToEdDSA(t *testing.T) {
	var server *httptest.Server

	server = httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{
				"jwks_uri": %q
			}`, server.URL+"/jwks")
		}),
	)
	defer server.Close()

	r := NewResolver(context.Background())
	r.client = server.Client()

	config, err := r.DiscoverIssuer(
		context.Background(),
		&evp_domain.IssuerMetadata{
			Issuer: server.URL,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(config.SigningAlgorithmsSupported) != 1 ||
		config.SigningAlgorithmsSupported[0] != "EdDSA" {
		t.Fatalf(
			"expected EdDSA default, got %#v",
			config.SigningAlgorithmsSupported,
		)
	}
}

func TestNormalizeIssuer(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{
			raw:  "accounts.google.com",
			want: "accounts.google.com",
		},
		{
			raw:  "https://accounts.google.com",
			want: "accounts.google.com",
		},
		{
			raw:  "https://accounts.google.com/",
			want: "accounts.google.com",
		},
		{
			raw:     "http://accounts.google.com",
			wantErr: true,
		},
		{
			raw:     "https://user:pass@example.com",
			wantErr: true,
		},
		{
			raw:     "https://example.com?x=1",
			wantErr: true,
		},
		{
			raw:     "https://example.com#fragment",
			wantErr: true,
		},
		{
			raw:     "",
			wantErr: true,
		},
		{
			raw:     "https://",
			wantErr: true,
		},
		{
			raw:  "  accounts.google.com  ",
			want: "accounts.google.com",
		}, {
			raw:     "https://example.com/foo",
			wantErr: true,
		},
		{
			raw:  "https://example.com:8443",
			want: "example.com:8443",
		},
		{
			raw:  "ACCOUNTS.GOOGLE.COM",
			want: "accounts.google.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := CanonicalIssuer(tt.raw)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}

			if got != tt.want {
				t.Fatalf(
					"expected %q, got %q",
					tt.want,
					got,
				)
			}
		})
	}
}

func TestDiscoverIssuer_Errors(t *testing.T) {
	tests := []struct {
		name   string
		issuer *evp_domain.IssuerMetadata
	}{
		{
			name:   "nil issuer",
			issuer: nil,
		},
		{
			name: "empty issuer",
			issuer: &evp_domain.IssuerMetadata{
				Issuer: "",
			},
		},
		{
			name: "http issuer rejected",
			issuer: &evp_domain.IssuerMetadata{
				Issuer: "http://issuer.example",
			},
		},
		{
			name: "missing host",
			issuer: &evp_domain.IssuerMetadata{
				Issuer: "https:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewResolver(context.Background())

			_, err := r.DiscoverIssuer(
				context.Background(),
				tt.issuer,
			)

			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDiscoverIssuer_Non200(t *testing.T) {
	server := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}),
	)
	defer server.Close()

	resolver := NewResolver(context.Background())
	resolver.client = server.Client()

	_, err := resolver.DiscoverIssuer(
		context.Background(),
		&evp_domain.IssuerMetadata{
			Issuer: server.URL,
		},
	)

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDiscoverIssuer_MalformedJSON(t *testing.T) {
	server := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{lol`)
		}),
	)
	defer server.Close()

	resolver := NewResolver(context.Background())
	resolver.client = server.Client()

	_, err := resolver.DiscoverIssuer(
		context.Background(),
		&evp_domain.IssuerMetadata{
			Issuer: server.URL,
		},
	)

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDiscoverIssuer_InvalidJWKS(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing jwks uri",
			body: `{
				"signing_alg_values_supported": ["EdDSA"]
			}`,
		},
		{
			name: "http jwks uri",
			body: `{
				"jwks_uri": "http://issuer.example/jwks",
				"signing_alg_values_supported": ["EdDSA"]
			}`,
		},
		{
			name: "relative jwks uri",
			body: `{
				"jwks_uri": "/jwks",
				"signing_alg_values_supported": ["EdDSA"]
			}`,
		},
		{
			name: "none algorithm passed",
			body: `{
				"jwks_uri": "https://issuer.example/jwks",
				"signing_alg_values_supported": ["none"]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(
				http.HandlerFunc(func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					fmt.Fprint(w, tt.body)
				}),
			)
			defer server.Close()

			resolver := NewResolver(context.Background())
			resolver.client = server.Client()

			_, err := resolver.DiscoverIssuer(
				context.Background(),
				&evp_domain.IssuerMetadata{
					Issuer: server.URL,
				},
			)

			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
