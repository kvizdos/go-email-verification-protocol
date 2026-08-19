package issuer

import "fmt"

var (
	ErrNoIssuerFound = fmt.Errorf("no EVP issuer found")
	ErrFailedLookup  = fmt.Errorf("failed to lookup EVP issuer")
)
