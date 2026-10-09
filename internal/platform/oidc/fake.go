package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Fake es un proveedor simulado para las pruebas y `pnpm e2e:http` (GOOGLE_PROVIDER=fake, solo dev).
// No habla con Google: `AuthURL` devuelve directamente la URL del callback de la API con un `code`
// que codifica una identidad de prueba, y `Exchange` lo decodifica.
//
// Formato del code (documentado aquí porque es el contrato del simulador):
//
//	code = "fk." + base64url(JSON({"sub","email","email_verified","name"}))
//
// El prefijo "fk." evita confundirlo con un código real de Google; un code que no empiece por "fk."
// o cuyo JSON no traiga `sub` y `email` se rechaza.
type Fake struct {
	CallbackURL string
	Identity    Identity
}

// NewFake crea el proveedor simulado apuntando al callback dado (p. ej.
// http://localhost:8080/v1/auth/google/callback) con una identidad por defecto.
func NewFake(callbackURL string) *Fake {
	return &Fake{
		CallbackURL: callbackURL,
		Identity: Identity{
			Subject:       "fake-google-subject",
			Email:         "google@example.com",
			EmailVerified: true,
			Name:          "Persona Google",
		},
	}
}

// AuthURL arma la URL del callback con el código de la identidad simulada y el `state` recibido.
func (f *Fake) AuthURL(state, _, _ string) string {
	u, err := url.Parse(f.CallbackURL)
	if err != nil {
		u = &url.URL{Path: f.CallbackURL}
	}
	q := u.Query()
	q.Set("code", encodeFakeIdentity(f.Identity))
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange decodifica el código de prueba. Ignora el verificador PKCE y el nonce (no hay id_token).
func (f *Fake) Exchange(_ context.Context, code, _, _ string) (*Identity, error) {
	return decodeFakeIdentity(code)
}

type fakeIdentity struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func encodeFakeIdentity(id Identity) string {
	raw, _ := json.Marshal(fakeIdentity{Sub: id.Subject, Email: id.Email, EmailVerified: id.EmailVerified, Name: id.Name})
	return "fk." + base64.RawURLEncoding.EncodeToString(raw)
}

func decodeFakeIdentity(code string) (*Identity, error) {
	if !strings.HasPrefix(code, "fk.") {
		return nil, errors.New("oidc: código simulado mal formado")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, "fk."))
	if err != nil {
		return nil, errors.New("oidc: código simulado ilegible")
	}
	var id fakeIdentity
	if err := json.Unmarshal(raw, &id); err != nil || id.Sub == "" || id.Email == "" {
		return nil, errors.New("oidc: identidad simulada inválida")
	}
	return &Identity{Subject: id.Sub, Email: id.Email, EmailVerified: id.EmailVerified, Name: id.Name}, nil
}
