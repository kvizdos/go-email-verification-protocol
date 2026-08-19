# go-email-verification-protocol

A small Go implementation of the **Email Verification Protocol (EVP)** verifier flow.

EVP lets a browser prove that a user controls an email address through their email provider, without requiring your application to send a verification email, magic link, or one-time code.

This package is intended to hide the protocol details behind a small Go API:

```go
result, err := evp.Verify(ctx, token, evp.Options{
    Email:    "user@gmail.com",
    Nonce:    nonce,
    Audience: "https://example.com",
})
if err != nil {
    // Fall back to your normal email verification flow.
}

if result.Verified {
    // The email address was verified by its provider.
}
```

## What is EVP?

The Email Verification Protocol is an emerging browser protocol for verifying ownership of an email address.

Instead of this:

```text
User enters email
      ↓
Application sends email
      ↓
User leaves your site
      ↓
User clicks link / copies OTP
      ↓
Application verifies email
```

EVP enables this:

```text
User enters email
      ↓
Browser communicates with email provider
      ↓
Provider issues verification proof
      ↓
Browser submits proof with your form
      ↓
evp.Verify(...)
      ↓
Email verified
```

For supported browsers and email providers, this can make email verification effectively invisible to the user.

EVP should currently be treated as a **progressive enhancement**. If a browser does not provide an EVP token, or verification fails, applications should fall back to their existing email verification flow.

## Installation

```bash
go get github.com/kvizdos/go-email-verification-protocol
```

```go
import evp "github.com/kvizdos/go-email-verification-protocol"
```

## Usage

Your form contains the user's email address and an EVP token field:

```html
<input
    name="email"
    type="email"
    autocomplete="email">

<input
    name="email_verification_token"
    type="hidden"
    nonce="YOUR_SESSION_NONCE"
    autocomplete="email-verification-token">
```

When the form is submitted, pass the token and the values you expect into `evp.Verify`:

```go
result, err := evp.Verify(r.Context(), r.FormValue("email_verification_token"), evp.Options{
    Email:    r.FormValue("email"),
    Nonce:    expectedNonce,
    Audience: "https://example.com",
})
if err != nil {
    // EVP unavailable or invalid.
    // Continue with your normal verification email / OTP flow.
    return
}

if result.Verified {
    // Email ownership has been verified.
}
```

## What `Verify` does

`evp.Verify` performs the verifier-side validation required by EVP, including:

1. Parsing the submitted SD-JWT + key-binding proof.
2. Validating expected claims such as:
   - email address
   - `email_verified`
   - nonce
   - audience
   - issuance time
3. Verifying the browser's key-binding signature.
4. Verifying the token hash binding.
5. Looking up the email domain's `_email-verification` DNS record.
6. Confirming that the token issuer matches the provider delegated by DNS.
7. Discovering the issuer's `/.well-known/email-verification` configuration.
8. Fetching the issuer's JWKS.
9. Verifying the Email Verification Token signature.

The goal is that applications should not need to understand or independently implement those protocol steps.

## Proposed API

The public API is intentionally small:

```go
type Options struct {
    // Email is the address your application expects to have been verified.
    Email string

    // Nonce is the session-bound nonce placed on the EVP form field.
    Nonce string

    // Audience is the origin of the relying party, for example:
    // https://example.com
    Audience string
}

type Result struct {
    Verified bool
    Email    string
    Issuer   string
}

func Verify(
    ctx context.Context,
    token string,
    options Options,
) (*Result, error)
```

Usage should remain approximately:

```go
result, err := evp.Verify(ctx, token, evp.Options{
    Email:    email,
    Nonce:    nonce,
    Audience: "https://example.com",
})
```

rather than requiring applications to directly deal with SD-JWT parsing, JOSE, DNS discovery, issuer metadata, JWKs, or key binding.

## Progressive enhancement

EVP is not intended to make your existing email verification path disappear.

A typical integration should look like:

```go
if token != "" {
    result, err := evp.Verify(ctx, token, evp.Options{
        Email:    email,
        Nonce:    nonce,
        Audience: origin,
    })

    if err == nil && result.Verified {
        markEmailVerified(email)
        return
    }
}

sendVerificationEmail(email)
```

If EVP succeeds, skip the verification email.

If EVP is unsupported, absent, or invalid, nothing breaks.

## Protocol status

The Email Verification Protocol and browser implementation are still evolving and may introduce backwards-incompatible changes while the proposal is being developed.

This library aims to track the current protocol while presenting a stable, minimal verifier API to Go applications.

## Scope

The initial scope of this project is the **relying-party / verifier side** of EVP.

In other words:

```go
evp.Verify(...)
```

Issuer-side support may be added separately in the future.

## References

- [Chrome: Test the Email Verification Protocol with an origin trial](https://developer.chrome.com/blog/email-verification-protocol-origin-trial)
- [WICG Email Verification](https://github.com/WICG/email-verification)
- [Email Verification Protocol draft](https://www.ietf.org/archive/id/draft-hardt-email-verification-00.html)

## License

MIT
