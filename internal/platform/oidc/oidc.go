// Package oidc define el puerto de identidad externa (Google) y sus adaptadores.
//
// Sigue el patrón de internal/platform/mailer: los módulos de negocio solo conocen la interfaz
// Provider; para añadir otro proveedor se escribe un adaptador nuevo y se registra en New.
package oidc

import "context"

// Identity es lo que un proveedor demuestra sobre la persona: un identificador estable (`sub`), su
// correo (verificado) y su nombre. No incluye ningún secreto: Google solo dice quién es, no abre
// ninguna clave de AxoNote.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Provider es el puerto. AuthURL construye la URL de autorización (a la que el navegador navega) y
// Exchange canjea el código de autorización por la identidad, validando el `nonce` y el PKCE propios
// del servidor.
type Provider interface {
	AuthURL(state, nonce, pkceChallenge string) string
	Exchange(ctx context.Context, code, pkceVerifier, nonce string) (*Identity, error)
}
