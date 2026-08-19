package evp_domain

import (
	"time"
)

type VerifyOptions struct {
	Email    string
	Nonce    string
	Audience string

	// Optional policy knobs.
	MaxAge time.Duration
}
