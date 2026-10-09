package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testClientID = "client-1"

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwksFor(t *testing.T, kid string, pub *rsa.PublicKey) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{
		{"kty": "RSA", "kid": kid, "n": n, "e": e, "alg": "RS256", "use": "sig"},
	}})
	return string(b)
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testGoogle(t *testing.T, jwks, idToken string, certsCalls *int32) *Google {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		if certsCalls != nil {
			atomic.AddInt32(certsCalls, 1)
		}
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, jwks)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewGoogle(GoogleOptions{
		ClientID: testClientID, ClientSecret: "secret", RedirectURL: "http://api/cb",
		AuthEndpoint: srv.URL + "/auth", TokenEndpoint: srv.URL + "/token", CertsURL: srv.URL + "/certs",
	})
}

func baseClaims(nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": testClientID, "sub": "sub-123",
		"email": "ana@example.com", "email_verified": true, "name": "Ana",
		"exp": 1893456000, "iat": 1693456000, "nonce": nonce,
	}
}

func TestGoogleAuthURL(t *testing.T) {
	g := NewGoogle(GoogleOptions{ClientID: "cid", ClientSecret: "s", RedirectURL: "https://api/cb"})
	u := g.AuthURL("state-token", "nonce-1", "challenge-1")
	for _, want := range []string{"response_type=code", "code_challenge_method=S256", "prompt=select_account",
		"scope=openid+email+profile", "client_id=cid", "state=state-token", "nonce=nonce-1",
		"code_challenge=challenge-1", "redirect_uri=https%3A%2F%2Fapi%2Fcb"} {
		if !strings.Contains(u, want) {
			t.Errorf("AuthURL no contiene %q: %s", want, u)
		}
	}
}

func TestGoogleExchangeValidatesIDToken(t *testing.T) {
	key := newKey(t)
	const nonce = "nonce-abc"
	valid := signToken(t, key, "k1", baseClaims(nonce))

	mutated := func(mut func(jwt.MapClaims)) string {
		c := baseClaims(nonce)
		mut(c)
		return signToken(t, key, "k1", c)
	}
	audBad := mutated(func(c jwt.MapClaims) { c["aud"] = "otro-cliente" })
	issBad := mutated(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" })
	expired := mutated(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(nonce))
	noneTok.Header["kid"] = "k1"
	noneSigned, _ := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType)

	cases := []struct {
		name  string
		token string
		nonce string
		ok    bool
	}{
		{"válido", valid, nonce, true},
		{"iss accounts.google.com sin esquema", signToken(t, key, "k1", func() jwt.MapClaims {
			c := baseClaims(nonce)
			c["iss"] = "accounts.google.com"
			return c
		}()), nonce, true},
		{"aud incorrecta", audBad, nonce, false},
		{"iss incorrecto", issBad, nonce, false},
		{"nonce incorrecto", valid, "otro-nonce", false},
		{"vencido", expired, nonce, false},
		{"firma ajena", signToken(t, newKey(t), "k1", baseClaims(nonce)), nonce, false},
		{"kid desconocido", signToken(t, key, "k2", baseClaims(nonce)), nonce, false},
		{"alg none", noneSigned, nonce, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := testGoogle(t, jwksFor(t, "k1", &key.PublicKey), tc.token, nil)
			_, err := g.Exchange(context.Background(), "code", "verifier", tc.nonce)
			if tc.ok && err != nil {
				t.Fatalf("debería aceptar: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("debería rechazar")
			}
		})
	}
}

func TestGoogleExchangeReturnsIdentity(t *testing.T) {
	key := newKey(t)
	g := testGoogle(t, jwksFor(t, "k1", &key.PublicKey), signToken(t, key, "k1", baseClaims("n1")), nil)
	id, err := g.Exchange(context.Background(), "code", "verifier", "n1")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "sub-123" || id.Email != "ana@example.com" || !id.EmailVerified || id.Name != "Ana" {
		t.Fatalf("identidad: %+v", id)
	}
}

func TestGoogleCertsAreCached(t *testing.T) {
	key := newKey(t)
	var calls int32
	g := testGoogle(t, jwksFor(t, "k1", &key.PublicKey), signToken(t, key, "k1", baseClaims("n1")), &calls)
	for i := 0; i < 3; i++ {
		if _, err := g.Exchange(context.Background(), "code", "verifier", "n1"); err != nil {
			t.Fatal(err)
		}
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("las claves debían cachearse: %d descargas", calls)
	}
}

func TestFakeProviderRoundTrip(t *testing.T) {
	f := NewFake("http://api.test/v1/auth/google/callback")
	f.Identity = Identity{Subject: "s1", Email: "g@example.com", EmailVerified: true, Name: "G"}
	u := f.AuthURL("state-1", "nonce", "chal")
	if !strings.HasPrefix(u, "http://api.test/v1/auth/google/callback?") {
		t.Fatalf("AuthURL: %s", u)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.Exchange(context.Background(), parsed.Query().Get("code"), "", "")
	if err != nil || id.Subject != "s1" || id.Email != "g@example.com" {
		t.Fatalf("Exchange simulado: %+v %v", id, err)
	}
	if parsed.Query().Get("state") != "state-1" {
		t.Fatalf("el state debe viajar: %s", u)
	}
	if _, err := f.Exchange(context.Background(), "no-es-un-code", "", ""); err == nil {
		t.Fatal("un code ajeno debía rechazarse")
	}
}
