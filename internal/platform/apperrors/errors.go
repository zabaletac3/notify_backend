// Package apperrors define los errores de dominio y su correspondencia con HTTP.
package apperrors

import (
	"errors"
	"net/http"
)

var (
	ErrNotFound           = errors.New("resource not found")
	ErrInvalidInput       = errors.New("invalid input")
	ErrConflict           = errors.New("resource conflict")
	ErrUnauthorized       = errors.New("missing or invalid credentials")
	ErrForbidden          = errors.New("forbidden")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTooManyRequests    = errors.New("too many requests, try again later")
	ErrPayloadTooLarge    = errors.New("payload too large")
	ErrServiceUnavailable = errors.New("service temporarily unavailable")
)

// HTTPStatus traduce un error a su código HTTP. Lo desconocido es 500.
func HTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrInvalidCredentials):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrTooManyRequests):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrPayloadTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// PublicMessage es el texto que puede ver quien llama. Los errores desconocidos
// nunca exponen detalles internos.
func PublicMessage(err error) string {
	if HTTPStatus(err) == http.StatusInternalServerError {
		return "internal server error"
	}
	return err.Error()
}
