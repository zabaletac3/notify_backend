// Package apperrors define los errores que la API entrega al cliente. Su forma JSON es la del
// `AppError` de la web (docs/api/openapi.yaml, esquema Error): {kind, code?, fields?, ...}.
package apperrors

import (
	"errors"
	"net/http"
	"time"
)

// Kind es la categoría del error, igual que `AppError['kind']` en el cliente.
type Kind string

const (
	KindServer         Kind = "server"
	KindUnauthorized   Kind = "unauthorized"
	KindForbidden      Kind = "forbidden"
	KindSessionExpired Kind = "session-expired"
	KindDeviceRevoked  Kind = "device-revoked"
	KindNotFound       Kind = "not-found"
	KindValidation     Kind = "validation"
	KindConflict       Kind = "conflict"
	KindRateLimited    Kind = "rate-limited"
)

// Error es el único error que llega al cliente. Err guarda la causa interna: se registra en el log
// y nunca se serializa.
type Error struct {
	Kind       Kind
	Code       string
	Fields     map[string]string
	Entity     string
	RetryAfter time.Duration
	Status     int // anula el estado HTTP que corresponde al Kind (p. ej. 413)
	Err        error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return string(e.Kind) + ": " + e.Err.Error()
	}
	return string(e.Kind)
}

func (e *Error) Unwrap() error { return e.Err }

// HTTPStatus es el código HTTP del error.
func (e *Error) HTTPStatus() int {
	if e.Status != 0 {
		return e.Status
	}
	switch e.Kind {
	case KindUnauthorized, KindSessionExpired, KindDeviceRevoked:
		return http.StatusUnauthorized
	case KindForbidden:
		return http.StatusForbidden
	case KindNotFound:
		return http.StatusNotFound
	case KindValidation:
		return http.StatusUnprocessableEntity
	case KindConflict:
		return http.StatusConflict
	case KindRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// Constructores.

func Unauthorized(code string) *Error { return &Error{Kind: KindUnauthorized, Code: code} }
func InvalidCredentials() *Error      { return Unauthorized("invalid-credentials") }
func Forbidden(code string) *Error    { return &Error{Kind: KindForbidden, Code: code} }
func SessionExpired() *Error          { return &Error{Kind: KindSessionExpired} }
func DeviceRevoked() *Error           { return &Error{Kind: KindDeviceRevoked} }
func NotFound(entity string) *Error   { return &Error{Kind: KindNotFound, Entity: entity} }
func Conflict(code string) *Error     { return &Error{Kind: KindConflict, Code: code} }

// Validation: campo → código de validación (ver ValidationCode en el contrato).
func Validation(fields map[string]string) *Error {
	return &Error{Kind: KindValidation, Fields: fields}
}

// RateLimited incluye cuánto falta para reintentar.
func RateLimited(retryAfter time.Duration) *Error {
	return &Error{Kind: KindRateLimited, RetryAfter: retryAfter}
}

// Internal envuelve un fallo inesperado; el cliente solo ve {kind:"server"}.
func Internal(err error) *Error { return &Error{Kind: KindServer, Err: err} }

// Unavailable: una dependencia necesaria (base de datos, limitador) no responde; se falla cerrado.
func Unavailable(err error) *Error {
	return &Error{Kind: KindServer, Status: http.StatusServiceUnavailable, Err: err}
}

// PayloadTooLarge: el cuerpo supera el límite.
func PayloadTooLarge() *Error {
	return &Error{Kind: KindValidation, Status: http.StatusRequestEntityTooLarge, Fields: map[string]string{"body": "invalid-payload"}}
}

// As convierte cualquier error en *Error; lo desconocido pasa a ser un error interno.
func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}
