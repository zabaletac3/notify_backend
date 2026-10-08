package apperrors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestHTTPStatus(t *testing.T) {
	cases := map[error]int{
		ErrNotFound:           http.StatusNotFound,
		ErrInvalidInput:       http.StatusBadRequest,
		ErrConflict:           http.StatusConflict,
		ErrUnauthorized:       http.StatusUnauthorized,
		ErrInvalidCredentials: http.StatusUnauthorized,
		ErrForbidden:          http.StatusForbidden,
		ErrTooManyRequests:    http.StatusTooManyRequests,
		ErrPayloadTooLarge:    http.StatusRequestEntityTooLarge,
		ErrServiceUnavailable: http.StatusServiceUnavailable,
		errors.New("boom"):    http.StatusInternalServerError,
	}
	for err, want := range cases {
		if got := HTTPStatus(fmt.Errorf("envuelto: %w", err)); got != want {
			t.Errorf("%v: got %d, want %d", err, got, want)
		}
	}
}

func TestPublicMessageHidesInternals(t *testing.T) {
	if got := PublicMessage(errors.New("password=hunter2 failed")); got != "internal server error" {
		t.Fatalf("filtró detalles internos: %q", got)
	}
}
