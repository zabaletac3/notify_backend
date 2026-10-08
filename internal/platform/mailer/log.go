package mailer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// LogMailer escribe el correo en el log en lugar de enviarlo. Solo para dev y
// QA: el contenido (códigos de verificación) queda visible en los logs, por eso
// la configuración lo prohíbe en prod.
//
// Además de la línea JSON, imprime el correo en texto legible en Out (por defecto
// la salida de errores) para encontrar el código sin buscar dentro del JSON.
type LogMailer struct {
	Log *slog.Logger
	Out io.Writer
}

func (l LogMailer) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	l.Log.InfoContext(ctx, "mail (no enviado: proveedor log)",
		"to", msg.To, "subject", msg.Subject, "text", msg.Text)
	out := l.Out
	if out == nil {
		out = os.Stderr
	}
	rule := strings.Repeat("─", 60)
	_, _ = fmt.Fprintf(out, "\n%s\n📧 Para: %s\n   Asunto: %s\n\n%s\n%s\n\n",
		rule, msg.To, msg.Subject, strings.TrimSpace(msg.Text), rule)
	return nil
}
