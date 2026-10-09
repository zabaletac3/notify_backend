package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Endpoints por defecto de Google (se pueden sustituir en las pruebas).
const (
	defaultAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultTokenEndpoint = "https://oauth2.googleapis.com/token" //nolint:gosec // URL pública de Google; no es una credencial
	defaultCertsURL      = "https://www.googleapis.com/oauth2/v3/certs"
)

// Issuers aceptados por Google (con y sin esquema).
var googleIssuers = map[string]bool{"https://accounts.google.com": true, "accounts.google.com": true}

// Google es el adaptador OAuth 2.0 de código de autorización con PKCE. No usa ningún SDK: solo
// net/http para el canje y github.com/golang-jwt/jwt/v5 para validar el id_token.
type Google struct {
	clientID     string
	clientSecret string
	redirectURL  string
	http         *http.Client

	authEndpoint  string
	tokenEndpoint string
	certsURL      string

	cache *certsCache
}

// GoogleOptions son los datos del adaptador; los endpoints se pueden fijar en las pruebas.
type GoogleOptions struct {
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	HTTPClient    *http.Client
	AuthEndpoint  string
	TokenEndpoint string
	CertsURL      string
}

// NewGoogle crea el adaptador con tiempos de espera y una caché de claves de Google vacía.
func NewGoogle(opt GoogleOptions) *Google {
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	g := &Google{
		clientID: opt.ClientID, clientSecret: opt.ClientSecret, redirectURL: opt.RedirectURL,
		http: client, authEndpoint: opt.AuthEndpoint, tokenEndpoint: opt.TokenEndpoint, certsURL: opt.CertsURL,
		cache: &certsCache{keys: map[string]*rsa.PublicKey{}},
	}
	if g.authEndpoint == "" {
		g.authEndpoint = defaultAuthEndpoint
	}
	if g.tokenEndpoint == "" {
		g.tokenEndpoint = defaultTokenEndpoint
	}
	if g.certsURL == "" {
		g.certsURL = defaultCertsURL
	}
	return g
}

// AuthURL arma la URL de autorización. `state` lleva el ticket del servidor, `nonce` ata el id_token
// a esta petición y `pkceChallenge` es el reto PKCE del propio servidor (nunca sale el verifier).
func (g *Google) AuthURL(state, nonce, pkceChallenge string) string {
	q := url.Values{}
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "select_account")
	return g.authEndpoint + "?" + q.Encode()
}

// Exchange canjea el código por la identidad. Envía el `client_secret` y el `code_verifier` (PKCE
// del servidor) y valida el id_token: firma RS256 contra las claves de Google, `iss`, `aud`, `exp` y
// `nonce`. Nunca se registra el código ni el id_token.
func (g *Google) Exchange(ctx context.Context, code, pkceVerifier, nonce string) (*Identity, error) {
	if code == "" {
		return nil, errors.New("oidc: código vacío")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", g.clientID)
	form.Set("client_secret", g.clientSecret)
	form.Set("redirect_uri", g.redirectURL)
	form.Set("code_verifier", pkceVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: petición de canje: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: canje: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: canje rechazado (HTTP %d)", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return nil, fmt.Errorf("oidc: respuesta de canje mal formada: %w", err)
	}
	if tok.IDToken == "" {
		return nil, errors.New("oidc: la respuesta de canje no trae id_token")
	}
	return g.verifyIDToken(ctx, tok.IDToken, nonce)
}

func (g *Google) verifyIDToken(ctx context.Context, raw, nonce string) (*Identity, error) {
	keyfunc := func(t *jwt.Token) (any, error) { return g.keyFor(ctx, t) }
	token, err := jwt.Parse(raw, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token inválido: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("oidc: id_token sin claims")
	}
	if iss, _ := claims["iss"].(string); !googleIssuers[iss] {
		return nil, errors.New("oidc: emisor inesperado")
	}
	if !audienceMatches(claims["aud"], g.clientID) {
		return nil, errors.New("oidc: audiencia inesperada")
	}
	if exp, ok := claimTime(claims["exp"]); !ok || !exp.After(time.Now()) {
		return nil, errors.New("oidc: id_token vencido")
	}
	if n, _ := claims["nonce"].(string); n == "" || n != nonce {
		return nil, errors.New("oidc: nonce no coincide")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("oidc: id_token sin sub")
	}
	id := &Identity{Subject: sub, Name: claimString(claims["name"])}
	id.Email, _ = claims["email"].(string)
	id.EmailVerified, _ = claims["email_verified"].(bool)
	return id, nil
}

// keyFor devuelve la clave RSA del `kid` del id_token; si no está en caché (o esta venció), recarga
// las claves de Google.
func (g *Google) keyFor(ctx context.Context, t *jwt.Token) (*rsa.PublicKey, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("oidc: id_token sin kid")
	}
	if k, ok := g.cache.get(kid); ok {
		return k, nil
	}
	if err := g.fetchCerts(ctx); err != nil {
		return nil, err
	}
	if k, ok := g.cache.get(kid); ok {
		return k, nil
	}
	return nil, errors.New("oidc: kid desconocido tras recargar las claves")
}

// fetchCerts descarga y guarda las claves, respetando el `Cache-Control: max-age` que envíe Google.
func (g *Google) fetchCerts(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.certsURL, nil)
	if err != nil {
		return fmt.Errorf("oidc: petición de claves: %w", err)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: claves: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: claves rechazadas (HTTP %d)", resp.StatusCode)
	}
	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return fmt.Errorf("oidc: claves mal formadas: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range body.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("oidc: Google no devolvió claves RSA")
	}
	g.cache.set(keys, cacheMaxAge(resp.Header.Get("Cache-Control")))
	return nil
}

// ── Caché de claves ─────────────────────────────────────────────

type certsCache struct {
	mu   sync.Mutex
	keys map[string]*rsa.PublicKey
	exp  time.Time
}

func (c *certsCache) get(kid string) (*rsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().After(c.exp) {
		return nil, false
	}
	k, ok := c.keys[kid]
	return k, ok
}

func (c *certsCache) set(keys map[string]*rsa.PublicKey, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
	c.exp = time.Now().Add(ttl)
}

func cacheMaxAge(header string) time.Duration {
	const def = time.Hour
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "max-age=") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
		if err != nil || n < 1 {
			return def
		}
		if n > 24*3600 {
			n = 24 * 3600
		}
		return time.Duration(n) * time.Second
	}
	return def
}

func rsaFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil || len(nBytes) == 0 {
		return nil, errors.New("oidc: n inválido")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("oidc: e inválido")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 3 {
		return nil, errors.New("oidc: exponente inválido")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func audienceMatches(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

func claimTime(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func claimString(v any) string {
	s, _ := v.(string)
	return s
}
