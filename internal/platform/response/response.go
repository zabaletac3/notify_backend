// Package response escribe las respuestas JSON de la API: el cuerpo es el del contrato
// (docs/api/openapi.yaml), sin envoltorio, y los errores tienen la forma de `AppError`.
package response

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
)

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body) // un cuerpo nil se envía como `null` (p. ej. «sin enlace»)
}

// JSON responde con el cuerpo tal cual.
func JSON(w http.ResponseWriter, status int, body any) { write(w, status, body) }

// NoContent responde 204 sin cuerpo.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

type errorBody struct {
	Kind          apperrors.Kind    `json:"kind"`
	Code          string            `json:"code,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
	Entity        string            `json:"entity,omitempty"`
	RetryAfterSec int               `json:"retryAfterSec,omitempty"`
}

// Error responde con el error del contrato. Los errores internos se registran (si hay logger) y el
// cliente solo recibe {kind:"server"}: nunca la causa.
func Error(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	e := apperrors.As(err)
	if e.Err != nil && log != nil {
		log.ErrorContext(r.Context(), "request failed", "kind", string(e.Kind), "path", routeOf(r), "err", e.Err.Error())
	}
	body := errorBody{Kind: e.Kind, Code: e.Code, Fields: e.Fields, Entity: e.Entity}
	if e.Kind == apperrors.KindRateLimited {
		secs := int((e.RetryAfter + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		body.RetryAfterSec = secs
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	write(w, e.HTTPStatus(), body)
}

// routeOf devuelve el patrón de la ruta (sin identificadores ni slugs) para los registros.
func routeOf(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if pat := rc.RoutePattern(); pat != "" {
			return pat
		}
	}
	return r.URL.Path
}
