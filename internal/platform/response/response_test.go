package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSuccessEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	Success(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil), http.StatusOK, map[string]string{"a": "b"})
	var got SuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Success || got.StatusCode != 200 || got.Path != "/x" {
		t.Fatalf("envoltorio inesperado: %+v", got)
	}
}

func TestFailHidesInternalError(t *testing.T) {
	rec := httptest.NewRecorder()
	Fail(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil), errors.New("conn string postgres://u:p@h"))
	if rec.Code != 500 || rec.Body.String() == "" {
		t.Fatalf("código %d", rec.Code)
	}
	if body := rec.Body.String(); contains(body, "postgres://") {
		t.Fatalf("filtró detalles: %s", body)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
