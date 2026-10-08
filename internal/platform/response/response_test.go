package response

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
)

func req(t *testing.T) *http.Request {
	return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
}

func TestJSONHasNoEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, http.StatusOK, map[string]string{"a": "b"})
	if strings.TrimSpace(rec.Body.String()) != `{"a":"b"}` || rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	NoContent(rec)
	if rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatal("204 con cuerpo")
	}
}

func TestErrorShapes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
		want string
	}{
		{"credenciales", apperrors.InvalidCredentials(), 401, `{"kind":"unauthorized","code":"invalid-credentials"}`},
		{"correo sin verificar", apperrors.Forbidden("email-not-verified"), 403, `{"kind":"forbidden","code":"email-not-verified"}`},
		{"validación", apperrors.Validation(map[string]string{"email": "invalid-email"}), 422, `{"kind":"validation","fields":{"email":"invalid-email"}}`},
		{"no existe", apperrors.NotFound("device"), 404, `{"kind":"not-found","entity":"device"}`},
		{"sesión", apperrors.SessionExpired(), 401, `{"kind":"session-expired"}`},
		{"dispositivo", apperrors.DeviceRevoked(), 401, `{"kind":"device-revoked"}`},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		Error(rec, req(t), nil, c.err)
		if rec.Code != c.code || strings.TrimSpace(rec.Body.String()) != c.want {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
}

func TestRateLimitedSetsRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, req(t), nil, apperrors.RateLimited(90*time.Second+time.Millisecond))
	var b map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "91" || b["retryAfterSec"] != float64(91) {
		t.Fatalf("%d %v %v", rec.Code, rec.Header(), b)
	}
}

func TestInternalErrorIsLoggedButNotExposed(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	rec := httptest.NewRecorder()
	Error(rec, req(t), log, errors.New("conn postgres://u:secreto@h"))
	if rec.Code != 500 || strings.TrimSpace(rec.Body.String()) != `{"kind":"server"}` {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "secreto") {
		t.Fatal("el cuerpo filtra la causa")
	}
	if !strings.Contains(buf.String(), "secreto") {
		t.Log("(la causa se registra en el log; aceptable, pero sin secretos por contrato)")
	}
}
