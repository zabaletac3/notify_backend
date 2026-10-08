// Package observability crea el logger JSON estructurado.
package observability

import (
	"io"
	"log/slog"
	"strings"
)

// NewLogger escribe JSON con atributos base fijos. Nunca registrar secretos,
// cuerpos de petición ni datos de personas.
func NewLogger(w io.Writer, level, service, env string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parseLevel(level)})
	return slog.New(h).With("service", service, "environment", env)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
