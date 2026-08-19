package evp_domain

type IssuerMetadata struct {
	Issuer string
}

type IssuerConfiguration struct {
	IssuanceEndpoint           string   `json:"issuance_endpoint"`
	JWKSURI                    string   `json:"jwks_uri"`
	SigningAlgorithmsSupported []string `json:"signing_alg_values_supported"`
}
