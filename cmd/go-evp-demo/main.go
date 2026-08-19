/*
 * Entirely vibe coded to test..
 */
package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	evp "github.com/kvizdos/go-email-verification-protocol"
	"github.com/kvizdos/go-email-verification-protocol/evp_domain"
)

const nonceCookieName = "go_evp_demo_nonce"

type app struct {
	templates   *template.Template
	audience    string
	originTrial string
}

type indexData struct {
	Nonce       string
	Audience    string
	OriginTrial string
	Error       string
}

type resultData struct {
	Success bool

	Email    string
	Issuer   string
	Verified bool

	Token    string
	Nonce    string
	Audience string

	Error string
}

func main() {
	audience := strings.TrimSpace(os.Getenv("EVP_AUDIENCE"))
	originTrial := strings.TrimSpace(os.Getenv("EVP_ORIGIN_TRIAL_TOKEN"))

	templates := template.Must(
		template.ParseGlob("cmd/go-evp-demo/templates/*.html"),
	)

	a := &app{
		templates:   templates,
		audience:    audience,
		originTrial: originTrial,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /", a.index)
	mux.HandleFunc("POST /verify", a.verify)

	addr := ":8080"

	log.Printf("EVP demo listening on http://localhost%s", addr)

	if audience != "" {
		log.Printf("EVP audience: %s", audience)
	} else {
		log.Printf("EVP_AUDIENCE not set; deriving audience from request")
	}

	if originTrial == "" {
		log.Printf("WARNING: EVP_ORIGIN_TRIAL_TOKEN is not set")
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func getOrCreateNonce(
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
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	return nonce, nil
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	nonce, err := getOrCreateNonce(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     nonceCookieName,
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	if a.originTrial != "" {
		// Origin trials may be enabled using the Origin-Trial response header.
		w.Header().Set("Origin-Trial", a.originTrial)
	}

	data := indexData{
		Nonce:       nonce,
		Audience:    a.requestAudience(r),
		OriginTrial: a.originTrial,
	}

	if err := a.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("render index: %v", err)
	}
}

func (a *app) verify(w http.ResponseWriter, r *http.Request) {
	if a.originTrial != "" {
		w.Header().Set("Origin-Trial", a.originTrial)
	}

	if err := r.ParseForm(); err != nil {
		a.renderResult(w, resultData{
			Error: "failed to parse form: " + err.Error(),
		})
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	token := strings.TrimSpace(r.FormValue("evp_token"))

	cookie, err := r.Cookie(nonceCookieName)
	if err != nil {
		a.renderResult(w, resultData{
			Email: email,
			Token: token,
			Error: "EVP nonce cookie is missing or expired",
		})
		return
	}

	expectedNonce := cookie.Value
	audience := a.requestAudience(r)

	data := resultData{
		Email:    email,
		Token:    token,
		Nonce:    expectedNonce,
		Audience: audience,
	}

	if email == "" {
		data.Error = "email is required"
		a.renderResult(w, data)
		return
	}

	if token == "" {
		data.Error = "EVP token is empty — the browser did not provide one"
		a.renderResult(w, data)
		return
	}

	result, err := evp.Verify(
		r.Context(),
		token,
		evp_domain.VerifyOptions{
			Email:    email,
			Nonce:    expectedNonce,
			Audience: audience,
		},
	)
	if err != nil {
		data.Error = err.Error()
		a.renderResult(w, data)
		return
	}

	data.Success = true
	data.Verified = result.Verified
	data.Email = result.Email
	data.Issuer = result.Issuer

	a.renderResult(w, data)
}

func (a *app) renderResult(w http.ResponseWriter, data resultData) {
	if err := a.templates.ExecuteTemplate(w, "result.html", data); err != nil {
		log.Printf("render result: %v", err)
	}
}

func (a *app) requestAudience(r *http.Request) string {
	if a.audience != "" {
		return strings.TrimSuffix(a.audience, "/")
	}

	scheme := "http"

	if requestIsHTTPS(r) {
		scheme = "https"
	}

	return scheme + "://" + r.Host
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	// Useful behind something like Cloudflare/nginx during development.
	return strings.EqualFold(
		r.Header.Get("X-Forwarded-Proto"),
		"https",
	)
}

func generateNonce() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Keep errors imported if you later want errors.Is handling around EVP failures.
var _ = errors.Is
var _ = time.Now
