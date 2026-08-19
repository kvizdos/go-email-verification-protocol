package evp_domain

import "errors"

var (
	ErrInvalidInput        = errors.New("invalid EVP input")
	ErrIssuerResolution    = errors.New("failed to resolve EVP issuer")
	ErrIssuerDiscovery     = errors.New("failed to discover EVP issuer")
	ErrUnauthorizedIssuer  = errors.New("unauthorized EVP issuer")
	ErrMalformedToken      = errors.New("malformed EVP token")
	ErrInvalidIssuerToken  = errors.New("invalid EVP issuer token")
	ErrEmailMismatch       = errors.New("verified email does not match expected email")
	ErrEmailNotVerified    = errors.New("issuer did not verify email")
	ErrInvalidKeyBinding   = errors.New("invalid EVP key binding")
	ErrNonceMismatch       = errors.New("EVP nonce mismatch")
	ErrAudienceMismatch    = errors.New("EVP audience mismatch")
	ErrTokenExpired        = errors.New("EVP token expired")
	ErrInvalidPresentation = errors.New("invalid EVP presentation")
)

type VerificationError struct {
	Stage string
	Err   error
}

func (e *VerificationError) Error() string {
	return e.Stage + ": " + e.Err.Error()
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}
