package oidc

import (
	"fmt"
	"log/slog"
)

// Options son los datos que necesita la fábrica; no depende de `config`.
type Options struct {
	Provider     string // off | google | fake
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// New elige el adaptador según el proveedor configurado. `off` devuelve (nil, nil): las rutas de
// Google existen pero responden `403 forbidden/google-disabled`.
func New(opt Options, log *slog.Logger) (Provider, error) {
	switch opt.Provider {
	case "off", "":
		return nil, nil
	case "google":
		if opt.ClientID == "" || opt.ClientSecret == "" || opt.RedirectURL == "" {
			return nil, fmt.Errorf("oidc: faltan datos de Google")
		}
		return NewGoogle(GoogleOptions{ClientID: opt.ClientID, ClientSecret: opt.ClientSecret, RedirectURL: opt.RedirectURL}), nil
	case "fake":
		if log != nil {
			log.Warn("GOOGLE_PROVIDER=fake: proveedor de identidad simulado (solo dev)")
		}
		return NewFake(opt.RedirectURL), nil
	default:
		return nil, fmt.Errorf("oidc: proveedor desconocido %q", opt.Provider)
	}
}
