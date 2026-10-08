// Package response escribe el envoltorio JSON común de la API.
package response

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
)

type SuccessEnvelope struct {
	Success    bool   `json:"success"`
	Data       any    `json:"data"`
	StatusCode int    `json:"statusCode"`
	Timestamp  string `json:"timestamp"`
	Path       string `json:"path"`
}

type ErrorEnvelope struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"statusCode"`
	Timestamp  string `json:"timestamp"`
	Path       string `json:"path"`
	Message    string `json:"message"`
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Success responde con el envoltorio de éxito.
func Success(w http.ResponseWriter, r *http.Request, status int, data any) {
	write(w, status, SuccessEnvelope{
		Success: true, Data: data, StatusCode: status,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Path: r.URL.Path,
	})
}

// Error responde con un mensaje ya seguro para mostrar.
func Error(w http.ResponseWriter, r *http.Request, status int, message string) {
	write(w, status, ErrorEnvelope{
		Success: false, StatusCode: status, Message: message,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Path: r.URL.Path,
	})
}

// Fail traduce un error de dominio a respuesta, sin exponer detalles internos.
func Fail(w http.ResponseWriter, r *http.Request, err error) {
	Error(w, r, apperrors.HTTPStatus(err), apperrors.PublicMessage(err))
}
