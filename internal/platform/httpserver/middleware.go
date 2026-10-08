package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/go-chi/chi/v5"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

type traceKey struct{}

var traceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// TraceIDFrom devuelve el id de traza de la petición.
func TraceIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(traceKey{}).(string)
	return v
}

// TraceID acepta x-trace-id solo si tiene forma segura (evita inyectar basura en logs).
func TraceID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("x-trace-id")
		if !traceRe.MatchString(id) {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("x-trace-id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), traceKey{}, id)))
	})
}

// Recover captura pánicos: registra la pila y responde un 500 genérico.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic recovered", "panic", rec, "stack", string(debug.Stack()),
						"traceId", TraceIDFrom(r.Context()))
					response.Error(w, r, log, apperrors.Internal(fmt.Errorf("panic: %v", rec)))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int)        { s.status = code; s.ResponseWriter.WriteHeader(code) }
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Logging registra una línea por petición. No incluye query, cabeceras ni cuerpo.
func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			// Se registra el patrón de la ruta (/v1/public/notes/{slug}), no la URL: así ni identificadores de
			// notas ni slugs de enlaces públicos acaban en los registros.
			path := r.URL.Path
			if rc := chi.RouteContext(r.Context()); rc != nil {
				if pat := rc.RoutePattern(); pat != "" {
					path = pat
				}
			}
			log.Info("http request",
				"method", r.Method, "path", path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"traceId", TraceIDFrom(r.Context()))
		})
	}
}

// SecurityHeaders añade las cabeceras de una API solo JSON.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-site")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// MaxBody limita el tamaño del cuerpo y rechaza cuerpos declarados demasiado grandes. `overrides`
// fija otro límite para rutas concretas (p. ej. /v1/sync, que lleva notas cifradas).
func MaxBody(limit int64, overrides map[string]int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := limit
			if o, ok := overrides[r.URL.Path]; ok {
				l = o
			}
			if r.ContentLength > l {
				response.Error(w, r, nil, apperrors.PayloadTooLarge())
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, l)
			next.ServeHTTP(w, r)
		})
	}
}
