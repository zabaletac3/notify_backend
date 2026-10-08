package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

// Live indica que el proceso responde.
func Live(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready indica que las dependencias están disponibles. No revela el motivo.
func Ready(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			response.Error(w, r, nil, apperrors.Unavailable(err))
			return
		}
		response.JSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
