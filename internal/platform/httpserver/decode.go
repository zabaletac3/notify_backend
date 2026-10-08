package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
)

// DecodeJSON lee un cuerpo JSON estricto: tipo de contenido correcto, sin campos desconocidos y
// sin datos de más. Devuelve un *apperrors.Error listo para responder.
func DecodeJSON(r *http.Request, v any) error {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return apperrors.Validation(map[string]string{"body": "invalid-payload"})
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return apperrors.PayloadTooLarge()
		}
		return apperrors.Validation(map[string]string{"body": "invalid-payload"})
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return apperrors.Validation(map[string]string{"body": "invalid-payload"})
	}
	return nil
}
