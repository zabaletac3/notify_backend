package share

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/zabaletac3/notify_backend/internal/platform/apperrors"
	"github.com/zabaletac3/notify_backend/internal/platform/httpserver"
	"github.com/zabaletac3/notify_backend/internal/platform/response"
)

// PrincipalFunc la aporta el módulo auth (que también protege las rutas privadas).
type PrincipalFunc func(ctx context.Context) (userID string, ok bool)

type Handler struct {
	svc        *Service
	log        *slog.Logger
	principal  PrincipalFunc
	trustProxy bool
}

func NewHandler(svc *Service, log *slog.Logger, principal PrincipalFunc, trustProxy bool) *Handler {
	return &Handler{svc: svc, log: log, principal: principal, trustProxy: trustProxy}
}

// PrivateRoutes cuelgan de un grupo que ya exige sesión.
func (h *Handler) PrivateRoutes(r chi.Router) {
	r.Get("/notes/{noteId}/share", h.get)
	r.Put("/notes/{noteId}/share", h.create)
	r.Delete("/notes/{noteId}/share", h.revoke)
	r.Put("/notes/{noteId}/share/payload", h.updatePayload)
}

// PublicRoutes no exigen sesión.
func (h *Handler) PublicRoutes(r chi.Router) {
	r.Get("/public/notes/{slug}", h.public)
}

func (h *Handler) user(r *http.Request) (string, error) {
	id, ok := h.principal(r.Context())
	if !ok {
		return "", apperrors.SessionExpired()
	}
	return id, nil
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	response.Error(w, r, h.log, err)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	uid, err := h.user(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	l, err := h.svc.Get(r.Context(), uid, chi.URLParam(r, "noteId"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if l == nil {
		response.JSON(w, http.StatusOK, nil) // el contrato devuelve `null` si no hay enlace
		return
	}
	response.JSON(w, http.StatusOK, l)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	uid, err := h.user(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var in ShareInput
	if err := httpserver.DecodeJSON(r, &in); err != nil {
		h.fail(w, r, err)
		return
	}
	l, err := h.svc.Create(r.Context(), uid, chi.URLParam(r, "noteId"), &in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, l)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	uid, err := h.user(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.Revoke(r.Context(), uid, chi.URLParam(r, "noteId")); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

func (h *Handler) updatePayload(w http.ResponseWriter, r *http.Request) {
	uid, err := h.user(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var in struct {
		Payload string `json:"payload"`
	}
	if err := httpserver.DecodeJSON(r, &in); err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.UpdatePayload(r.Context(), uid, chi.URLParam(r, "noteId"), in.Payload); err != nil {
		h.fail(w, r, err)
		return
	}
	response.NoContent(w)
}

func (h *Handler) public(w http.ResponseWriter, r *http.Request) {
	// Cache-Control: no-store y Referrer-Policy: no-referrer ya los fija el middleware global.
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	n, err := h.svc.ReadPublic(r.Context(), httpserver.ClientIP(r, h.trustProxy), chi.URLParam(r, "slug"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, n)
}
