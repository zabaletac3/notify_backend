package mailer

import (
	"fmt"
	"log/slog"
)

// Options son los datos que necesita la fábrica; no depende de `config`.
type Options struct {
	Provider     string // log | resend
	From         string
	ResendAPIKey string
}

// New elige el adaptador según el proveedor configurado. Aquí se registra un
// proveedor nuevo.
func New(opt Options, log *slog.Logger) (Mailer, error) {
	switch opt.Provider {
	case "log":
		return LogMailer{Log: log}, nil
	case "resend":
		if opt.ResendAPIKey == "" {
			return nil, fmt.Errorf("mailer: falta la clave de Resend")
		}
		return NewResend(opt.ResendAPIKey, opt.From, ""), nil
	default:
		return nil, fmt.Errorf("mailer: proveedor desconocido %q", opt.Provider)
	}
}
