package account

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

// PrincipalFunc la aporta el módulo auth (que también protege las rutas).
type PrincipalFunc func(ctx context.Context) (userID string, ok bool)

type Handler struct {
	svc       *Service
	log       *slog.Logger
	principal PrincipalFunc
}

func NewHandler(svc *Service, log *slog.Logger, principal PrincipalFunc) *Handler {
	return &Handler{svc: svc, log: log, principal: principal}
}

// Routes cuelgan de un grupo que ya exige sesión.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/settings", h.getSettings)
	r.Patch("/settings", h.patchSettings)
	r.Get("/storage/usage", h.usage)
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := h.principal(r.Context())
	if !ok {
		response.Error(w, r, h.log, apperrors.SessionExpired())
	}
	return id, ok
}

func (h *Handler) getSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	s, err := h.svc.Get(r.Context(), uid)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, s)
}

func (h *Handler) patchSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	var p SettingsPatch
	if err := httpserver.DecodeJSON(r, &p); err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	s, err := h.svc.Update(r.Context(), uid, &p)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, s)
}

func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	u, err := h.svc.Usage(r.Context(), uid)
	if err != nil {
		response.Error(w, r, h.log, err)
		return
	}
	response.JSON(w, http.StatusOK, u)
}
