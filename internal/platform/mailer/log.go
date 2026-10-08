package mailer

import (
	"context"
	"log/slog"
)

// LogMailer escribe el correo en el log en lugar de enviarlo. Solo para dev y
// QA: el contenido (códigos de verificación) queda visible en los logs, por eso
// la configuración lo prohíbe en prod.
type LogMailer struct{ Log *slog.Logger }

func (l LogMailer) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	l.Log.InfoContext(ctx, "mail (no enviado: proveedor log)",
		"to", msg.To, "subject", msg.Subject, "text", msg.Text)
	return nil
}
