package mailer

import (
	"fmt"
	"log/slog"
)

// Options son los datos que necesita la fábrica; no depende de `config`.
type Options struct {
	Provider     string // log | resend | smtp
	From         string
	ResendAPIKey string
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
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
	case "smtp":
		if opt.SMTPHost == "" || opt.SMTPUser == "" || opt.SMTPPassword == "" {
			return nil, fmt.Errorf("mailer: faltan datos de SMTP")
		}
		return NewSMTP(opt.SMTPHost, opt.SMTPPort, opt.SMTPUser, opt.SMTPPassword, opt.From)
	default:
		return nil, fmt.Errorf("mailer: proveedor desconocido %q", opt.Provider)
	}
}
