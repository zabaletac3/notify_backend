package apperrors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestHTTPStatus(t *testing.T) {
	cases := map[*Error]int{
		Unauthorized("x"):               http.StatusUnauthorized,
		InvalidCredentials():            http.StatusUnauthorized,
		SessionExpired():                http.StatusUnauthorized,
		DeviceRevoked():                 http.StatusUnauthorized,
		Forbidden("email-not-verified"): http.StatusForbidden,
		NotFound("note"):                http.StatusNotFound,
		Validation(nil):                 http.StatusUnprocessableEntity,
		Conflict("x"):                   http.StatusConflict,
		RateLimited(time.Second):        http.StatusTooManyRequests,
		Internal(errors.New("x")):       http.StatusInternalServerError,
		Unavailable(nil):                http.StatusServiceUnavailable,
		PayloadTooLarge():               http.StatusRequestEntityTooLarge,
	}
	for e, want := range cases {
		if got := e.HTTPStatus(); got != want {
			t.Errorf("%s: got %d, want %d", e.Kind, got, want)
		}
	}
}

func TestAsWrapsUnknownAsInternal(t *testing.T) {
	e := As(fmt.Errorf("conn postgres://u:p@h: %w", errors.New("boom")))
	if e.Kind != KindServer || e.Err == nil {
		t.Fatalf("%+v", e)
	}
	known := fmt.Errorf("envuelto: %w", NotFound("note"))
	if As(known).Kind != KindNotFound {
		t.Fatal("As no encuentra el error envuelto")
	}
}
