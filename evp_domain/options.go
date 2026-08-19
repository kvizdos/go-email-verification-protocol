package evp_domain

import (
	"time"
)

const (
	DefaultEVTMaxAge = 5 * time.Minute
	DefaultKBMaxAge  = 5 * time.Minute
)

type VerifyOptions struct {
	Email    string
	Nonce    string
	Audience string

	// Optional policy knobs.
	KBMaxAge  time.Duration
	EVTMaxAge time.Duration
}
