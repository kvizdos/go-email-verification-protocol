package go_email_verification_protocol

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

const nonceCookieName = "evp_nonce"

func GetOrCreateEVPNonce(
	w http.ResponseWriter,
	r *http.Request,
) (string, error) {
	if cookie, err := r.Cookie(nonceCookieName); err == nil {
		if cookie.Value != "" {
			return cookie.Value, nil
		}
	}

	nonce, err := generateNonce()
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     nonceCookieName,
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	return nonce, nil
}

func generateNonce() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
